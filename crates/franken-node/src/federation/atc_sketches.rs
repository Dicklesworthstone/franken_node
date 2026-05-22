//! bd-3ps8: Mergeable sketch system for scalable ecosystem pattern sharing (10.19).
//!
//! Implements deterministic, bounded-error mergeable sketches used by the ATC
//! federated intelligence track. Each participating deployment maintains a
//! local sketch summarizing observed threat indicators; sketches are merged at
//! the aggregator to recover ecosystem-wide frequency estimates while
//! preserving privacy and bounding bandwidth/compute.
//!
//! # Scope (MVP)
//!
//! - [`MergeableSketch`] trait — common contract for all sketch flavors.
//! - [`CountMinSketch`] (CMS) — frequency estimation with element-wise
//!   `saturating_add` merge semantics. Commutative and associative by
//!   construction (matrix addition over `saturating_add`-saturating naturals).
//! - [`ErrorBound`] — classical `(ε, δ)` Count-Min Sketch error bound where
//!   `width >= ceil(e/ε)` and `depth >= ceil(ln(1/δ))`.
//! - [`BudgetTracker`] — fail-closed enforcement of bandwidth (serialized
//!   bytes) and compute (insertions per round) budgets.
//!
//! HyperLogLog and Bloom sketches are intentionally left for follow-up beads
//! (`bd-3ps8.2`, `bd-3ps8.3`). CMS alone discharges the bd-3ps8 acceptance
//! criterion ("deterministic, bounded-error, budget-respecting merge").
//!
//! # Determinism
//!
//! All hashing uses a fixed domain separator (`b"atc_sketch_cms_v1:"`) fed
//! into the first `Hasher::update()` call, length-prefixed against ambiguity.
//! Hash seeds are derived from `(domain_separator, depth, width, row_index)`,
//! never from RNG. Two CMS instances constructed with identical `(depth,
//! width)` parameters produce identical seeds.
//!
//! # Invariants
//!
//! - **INV-ATC-SKETCH-DETERMINISM**: Same `(depth, width)` → same hash seeds.
//! - **INV-ATC-SKETCH-MERGE-COMMUTATIVE**: `a.merge(b) == b.merge(a)`.
//! - **INV-ATC-SKETCH-MERGE-ASSOCIATIVE**: `(a∘b)∘c == a∘(b∘c)`.
//! - **INV-ATC-SKETCH-OVERFLOW-SAFE**: Counter additions use `saturating_add`.
//! - **INV-ATC-SKETCH-ERROR-BOUND**: Reported `(ε, δ)` matches CMS theory.
//! - **INV-ATC-SKETCH-BUDGET-ENFORCED**: Over-budget operations fail closed.
//!
//! # Event codes
//!
//! See [`event_codes`] for the full catalog (`ATC-SKETCH-001..012`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::push_bounded;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Domain separator for all CMS seed derivations.
///
/// Mirrors the convention used elsewhere in the codebase: domain-separator
/// bytes are the **first** thing fed into the hasher so that no untrusted
/// input can collide with a different sketch family that happens to share
/// the same parameter triple.
pub const CMS_DOMAIN_SEPARATOR: &[u8] = b"atc_sketch_cms_v1:";

/// Hard ceiling on sketch dimensions to prevent accidental allocations on the
/// order of `depth * width * 8` bytes (which can balloon into GiB territory).
pub const MAX_CMS_DEPTH: u32 = 32;
pub const MAX_CMS_WIDTH: u32 = 1 << 20; // 1 Mi cells per row, ~8 MiB at u64.

/// Default bandwidth ceiling per round (per participant), 1 MiB. Tunable via
/// [`BudgetTracker::with_bandwidth`].
pub const DEFAULT_BANDWIDTH_BYTES: u64 = 1 << 20;

/// Default compute ceiling per round (insertions). Tunable via
/// [`BudgetTracker::with_compute`].
pub const DEFAULT_COMPUTE_OPS: u64 = 10_000_000;

/// Bound on retained audit/error log entries to avoid unbounded growth under
/// adversarial input (matches the project-wide hardening convention).
pub const MAX_BUDGET_EVENTS: usize = 1024;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// ATC-SKETCH-001: Count-Min Sketch constructed.
    pub const SKETCH_CONSTRUCTED: &str = "ATC-SKETCH-001";
    /// ATC-SKETCH-002: Sketch insertion succeeded.
    pub const SKETCH_INSERT: &str = "ATC-SKETCH-002";
    /// ATC-SKETCH-003: Sketch merge succeeded.
    pub const SKETCH_MERGE_OK: &str = "ATC-SKETCH-003";
    /// ATC-SKETCH-004: Sketch estimate emitted.
    pub const SKETCH_ESTIMATE: &str = "ATC-SKETCH-004";
    /// ATC-SKETCH-005: Sketch serialized for transport.
    pub const SKETCH_SERIALIZED: &str = "ATC-SKETCH-005";
    /// ATC-SKETCH-006: Sketch deserialized.
    pub const SKETCH_DESERIALIZED: &str = "ATC-SKETCH-006";
    /// ATC-SKETCH-007: Error bound computed.
    pub const ERROR_BOUND_COMPUTED: &str = "ATC-SKETCH-007";
    /// ATC-SKETCH-008: Bandwidth budget consumed.
    pub const BANDWIDTH_CONSUMED: &str = "ATC-SKETCH-008";
    /// ATC-SKETCH-009: Compute budget consumed.
    pub const COMPUTE_CONSUMED: &str = "ATC-SKETCH-009";
    /// ATC-SKETCH-ERR-001: Dimension mismatch on merge.
    pub const ERR_DIMENSION_MISMATCH: &str = "ATC-SKETCH-ERR-001";
    /// ATC-SKETCH-ERR-002: Bandwidth budget exceeded.
    pub const ERR_BANDWIDTH_EXCEEDED: &str = "ATC-SKETCH-ERR-002";
    /// ATC-SKETCH-ERR-003: Compute budget exceeded.
    pub const ERR_COMPUTE_EXCEEDED: &str = "ATC-SKETCH-ERR-003";
    /// ATC-SKETCH-ERR-004: Invalid sketch dimensions (zero or over cap).
    pub const ERR_INVALID_DIMENSIONS: &str = "ATC-SKETCH-ERR-004";
    /// ATC-SKETCH-ERR-005: Non-finite error parameter.
    pub const ERR_NON_FINITE_PARAM: &str = "ATC-SKETCH-ERR-005";
}

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_ATC_SKETCH_DETERMINISM: &str = "INV-ATC-SKETCH-DETERMINISM";
    pub const INV_ATC_SKETCH_MERGE_COMMUTATIVE: &str = "INV-ATC-SKETCH-MERGE-COMMUTATIVE";
    pub const INV_ATC_SKETCH_MERGE_ASSOCIATIVE: &str = "INV-ATC-SKETCH-MERGE-ASSOCIATIVE";
    pub const INV_ATC_SKETCH_OVERFLOW_SAFE: &str = "INV-ATC-SKETCH-OVERFLOW-SAFE";
    pub const INV_ATC_SKETCH_ERROR_BOUND: &str = "INV-ATC-SKETCH-ERROR-BOUND";
    pub const INV_ATC_SKETCH_BUDGET_ENFORCED: &str = "INV-ATC-SKETCH-BUDGET-ENFORCED";
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Fail-closed sketch operation error.
#[derive(Debug, Clone, PartialEq)]
pub enum SketchError {
    /// Two sketches with mismatched `(depth, width)` were merged.
    DimensionMismatch {
        lhs_depth: u32,
        lhs_width: u32,
        rhs_depth: u32,
        rhs_width: u32,
    },
    /// Bandwidth budget would be exceeded by the requested operation.
    BandwidthExceeded { requested: u64, remaining: u64 },
    /// Compute budget would be exceeded by the requested operation.
    ComputeExceeded { requested: u64, remaining: u64 },
    /// Dimensions are zero or exceed the configured ceiling.
    InvalidDimensions { depth: u32, width: u32 },
    /// `(ε, δ)` parameter contained NaN/inf or fell outside `(0, 1)`.
    NonFiniteParameter { name: &'static str, value: f64 },
    /// Serialized payload was malformed (corrupt header / truncated table).
    MalformedSerialization { reason: &'static str },
}

impl fmt::Display for SketchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DimensionMismatch {
                lhs_depth,
                lhs_width,
                rhs_depth,
                rhs_width,
            } => write!(
                f,
                "{}: lhs=({}, {}) rhs=({}, {})",
                event_codes::ERR_DIMENSION_MISMATCH,
                lhs_depth,
                lhs_width,
                rhs_depth,
                rhs_width
            ),
            Self::BandwidthExceeded {
                requested,
                remaining,
            } => write!(
                f,
                "{}: requested={} remaining={}",
                event_codes::ERR_BANDWIDTH_EXCEEDED,
                requested,
                remaining
            ),
            Self::ComputeExceeded {
                requested,
                remaining,
            } => write!(
                f,
                "{}: requested={} remaining={}",
                event_codes::ERR_COMPUTE_EXCEEDED,
                requested,
                remaining
            ),
            Self::InvalidDimensions { depth, width } => write!(
                f,
                "{}: depth={} width={}",
                event_codes::ERR_INVALID_DIMENSIONS,
                depth,
                width
            ),
            Self::NonFiniteParameter { name, value } => write!(
                f,
                "{}: name={} value={}",
                event_codes::ERR_NON_FINITE_PARAM,
                name,
                value
            ),
            Self::MalformedSerialization { reason } => {
                write!(f, "ATC-SKETCH-ERR-006: malformed serialization: {reason}")
            }
        }
    }
}

impl std::error::Error for SketchError {}

pub type SketchResult<T> = Result<T, SketchError>;

// ---------------------------------------------------------------------------
// Error bound
// ---------------------------------------------------------------------------

/// Classical Count-Min Sketch error bound.
///
/// For a CMS of width `w` and depth `d`, applied to a stream of frequencies
/// totalling `N`, the estimator's *additive* error is bounded by `eps * N`
/// with probability at least `1 - delta`, where:
///
/// - `eps = e / w`   (Euler's `e`, not the discriminant `delta`)
/// - `delta = e^{-d}`
///
/// Equivalently the minimum dimensions needed for target `(eps, delta)` are:
///
/// - `w_min = ceil(e / eps)`
/// - `d_min = ceil(ln(1/delta))`
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ErrorBound {
    /// Multiplicative error coefficient `eps` (per CMS theory; finite, > 0).
    pub eps: f64,
    /// Failure probability `delta` (finite, in (0, 1]).
    pub delta: f64,
}

impl ErrorBound {
    /// Confidence (1 - delta) expressed as a percentage in `[0, 100]`.
    pub fn confidence_pct(&self) -> f64 {
        let raw = (1.0 - self.delta) * 100.0;
        if !raw.is_finite() {
            return 0.0;
        }
        raw.clamp(0.0, 100.0)
    }
}

/// Compute the theoretical CMS error bound for the given dimensions.
///
/// Fails closed (`InvalidDimensions`) if either dimension is zero or beyond
/// the configured cap, since the bound formulas are undefined in those
/// regimes.
pub fn compute_error_bound(depth: u32, width: u32) -> SketchResult<ErrorBound> {
    if depth == 0 || width == 0 || depth > MAX_CMS_DEPTH || width > MAX_CMS_WIDTH {
        return Err(SketchError::InvalidDimensions { depth, width });
    }
    let e = std::f64::consts::E;
    let width_f = width as f64;
    let depth_f = depth as f64;
    // Guard inputs even though we've bounded them via the cap above.
    if !width_f.is_finite() || !depth_f.is_finite() {
        return Err(SketchError::NonFiniteParameter {
            name: "depth_or_width",
            value: 0.0,
        });
    }
    let eps = e / width_f;
    let delta = (-depth_f).exp();
    if !eps.is_finite() || !delta.is_finite() {
        return Err(SketchError::NonFiniteParameter {
            name: "computed_eps_or_delta",
            value: 0.0,
        });
    }
    Ok(ErrorBound { eps, delta })
}

// ---------------------------------------------------------------------------
// MergeableSketch trait
// ---------------------------------------------------------------------------

/// Common contract for ATC mergeable sketches.
pub trait MergeableSketch: Sized {
    /// Merge `other` into `self` in place. Implementations MUST be both
    /// commutative and associative — the merge operator forms a commutative
    /// monoid under the identity (empty sketch with matching dimensions).
    fn merge(&mut self, other: &Self) -> SketchResult<()>;

    /// Estimate the frequency / cardinality contribution of `key`.
    fn estimate(&self, key: &[u8]) -> u64;

    /// Theoretical error bound for the current dimensions.
    fn error_bound(&self) -> ErrorBound;

    /// Size in bytes of the canonical serialized representation.
    fn serialized_size(&self) -> usize;
}

// ---------------------------------------------------------------------------
// Count-Min Sketch
// ---------------------------------------------------------------------------

/// Count-Min Sketch with deterministic seed derivation and saturating-add
/// merge semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountMinSketch {
    depth: u32,
    width: u32,
    /// Row-major counter table of size `depth * width`.
    table: Vec<u64>,
    /// Per-row hash seeds (length `depth`).
    hash_seeds: Vec<u64>,
}

impl CountMinSketch {
    /// Construct a new, empty CMS with the requested dimensions.
    pub fn new(depth: u32, width: u32) -> SketchResult<Self> {
        if depth == 0 || width == 0 || depth > MAX_CMS_DEPTH || width > MAX_CMS_WIDTH {
            return Err(SketchError::InvalidDimensions { depth, width });
        }
        let cells = (depth as usize)
            .checked_mul(width as usize)
            .ok_or(SketchError::InvalidDimensions { depth, width })?;
        let hash_seeds = derive_hash_seeds(depth, width);
        Ok(Self {
            depth,
            width,
            table: vec![0u64; cells],
            hash_seeds,
        })
    }

    /// Construct CMS sized for target `(eps, delta)` bounds.
    pub fn for_bounds(eps: f64, delta: f64) -> SketchResult<Self> {
        if !eps.is_finite() || eps <= 0.0 || eps >= 1.0 {
            return Err(SketchError::NonFiniteParameter {
                name: "eps",
                value: eps,
            });
        }
        if !delta.is_finite() || delta <= 0.0 || delta >= 1.0 {
            return Err(SketchError::NonFiniteParameter {
                name: "delta",
                value: delta,
            });
        }
        let width = (std::f64::consts::E / eps).ceil();
        let depth = (1.0 / delta).ln().ceil();
        if !width.is_finite() || !depth.is_finite() || width <= 0.0 || depth <= 0.0 {
            return Err(SketchError::NonFiniteParameter {
                name: "computed_dim",
                value: 0.0,
            });
        }
        // Saturating-cast clamps to MAX_CMS_*; downstream `new()` re-validates.
        let width_u = (width as u64).min(MAX_CMS_WIDTH as u64) as u32;
        let depth_u = (depth as u64).min(MAX_CMS_DEPTH as u64).max(1) as u32;
        Self::new(depth_u, width_u)
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    /// Total population (sum of saturating-added insertions on row 0).
    pub fn total_count(&self) -> u64 {
        // Row 0 holds the same population as every other row (each insert
        // touches one cell per row), but counter saturation can desync rows.
        // Use the *minimum* row sum as the most conservative lower bound.
        let width = self.width as usize;
        if width == 0 || self.table.is_empty() {
            return 0;
        }
        let mut min_sum = u64::MAX;
        let mut observed = false;
        for row in 0..(self.depth as usize) {
            let start = row.saturating_mul(width);
            let end = start.saturating_add(width).min(self.table.len());
            if start >= end {
                continue;
            }
            observed = true;
            let row_sum: u64 = self.table[start..end]
                .iter()
                .fold(0u64, |acc, v| acc.saturating_add(*v));
            if row_sum < min_sum {
                min_sum = row_sum;
            }
        }
        if observed { min_sum } else { 0 }
    }

    /// Insert `count` observations of `key`.
    pub fn add(&mut self, key: &[u8], count: u64) {
        if count == 0 {
            return;
        }
        let width = self.width as usize;
        if width == 0 {
            return;
        }
        for row in 0..(self.depth as usize) {
            let seed = self.hash_seeds.get(row).copied().unwrap_or(0);
            let column = cell_column(seed, key, self.width);
            let idx = row.saturating_mul(width).saturating_add(column);
            if let Some(cell) = self.table.get_mut(idx) {
                *cell = cell.saturating_add(count);
            }
        }
    }

    /// Increment the count of `key` by 1.
    pub fn insert(&mut self, key: &[u8]) {
        self.add(key, 1);
    }
}

impl MergeableSketch for CountMinSketch {
    fn merge(&mut self, other: &Self) -> SketchResult<()> {
        if self.depth != other.depth || self.width != other.width {
            return Err(SketchError::DimensionMismatch {
                lhs_depth: self.depth,
                lhs_width: self.width,
                rhs_depth: other.depth,
                rhs_width: other.width,
            });
        }
        // Hash seeds are derived purely from dimensions, so equal dimensions
        // imply equal seeds — this check is belt-and-braces against tampered
        // deserializations.
        if self.hash_seeds != other.hash_seeds {
            return Err(SketchError::DimensionMismatch {
                lhs_depth: self.depth,
                lhs_width: self.width,
                rhs_depth: other.depth,
                rhs_width: other.width,
            });
        }
        if self.table.len() != other.table.len() {
            return Err(SketchError::DimensionMismatch {
                lhs_depth: self.depth,
                lhs_width: self.width,
                rhs_depth: other.depth,
                rhs_width: other.width,
            });
        }
        for (lhs, rhs) in self.table.iter_mut().zip(other.table.iter()) {
            *lhs = lhs.saturating_add(*rhs);
        }
        Ok(())
    }

    fn estimate(&self, key: &[u8]) -> u64 {
        let width = self.width as usize;
        if width == 0 || self.table.is_empty() {
            return 0;
        }
        let mut min_count = u64::MAX;
        let mut observed = false;
        for row in 0..(self.depth as usize) {
            let seed = self.hash_seeds.get(row).copied().unwrap_or(0);
            let column = cell_column(seed, key, self.width);
            let idx = row.saturating_mul(width).saturating_add(column);
            if let Some(cell) = self.table.get(idx) {
                observed = true;
                if *cell < min_count {
                    min_count = *cell;
                }
            }
        }
        // `observed` distinguishes "no rows hashed to a valid cell" (return 0)
        // from "every row landed on a counter saturated at u64::MAX" (which
        // would otherwise collide with the sentinel and incorrectly return 0).
        if observed { min_count } else { 0 }
    }

    fn error_bound(&self) -> ErrorBound {
        // Safe because new() rejects out-of-cap dimensions.
        compute_error_bound(self.depth, self.width).unwrap_or(ErrorBound {
            eps: f64::INFINITY,
            delta: 1.0,
        })
    }

    fn serialized_size(&self) -> usize {
        // 4 + 4 (depth, width) + 8*depth (seeds) + 8*depth*width (table)
        let seeds_bytes = (self.depth as usize).saturating_mul(8);
        let table_bytes = self.table.len().saturating_mul(8);
        8usize
            .saturating_add(seeds_bytes)
            .saturating_add(table_bytes)
    }
}

// ---------------------------------------------------------------------------
// Deterministic hashing
// ---------------------------------------------------------------------------

/// Derive per-row hash seeds from `(domain_separator, depth, width, row_index)`.
///
/// Uses SHA-256 (always available, deterministic, no feature flag dependency).
/// The bead spec references blake3 but blake3 is feature-gated to
/// `--features blake3` in this crate; sha2 has identical determinism semantics
/// and is the convention used elsewhere in the federation module
/// (e.g. `atc_reciprocity.rs`).
fn derive_hash_seeds(depth: u32, width: u32) -> Vec<u64> {
    let mut seeds = Vec::with_capacity(depth as usize);
    for row in 0..depth {
        let mut hasher = Sha256::new();
        // Domain separator first, length-prefixed, per project hardening conv.
        hasher.update((CMS_DOMAIN_SEPARATOR.len() as u64).to_le_bytes());
        hasher.update(CMS_DOMAIN_SEPARATOR);
        hasher.update(depth.to_le_bytes());
        hasher.update(width.to_le_bytes());
        hasher.update(row.to_le_bytes());
        let digest = hasher.finalize();
        let mut seed_bytes = [0u8; 8];
        seed_bytes.copy_from_slice(&digest[..8]);
        seeds.push(u64::from_le_bytes(seed_bytes));
    }
    seeds
}

/// Hash `key` under `seed` and reduce to a column index in `[0, width)`.
fn cell_column(seed: u64, key: &[u8], width: u32) -> usize {
    if width == 0 {
        return 0;
    }
    let mut hasher = Sha256::new();
    hasher.update((CMS_DOMAIN_SEPARATOR.len() as u64).to_le_bytes());
    hasher.update(CMS_DOMAIN_SEPARATOR);
    hasher.update(seed.to_le_bytes());
    hasher.update((key.len() as u64).to_le_bytes());
    hasher.update(key);
    let digest = hasher.finalize();
    let mut h_bytes = [0u8; 8];
    h_bytes.copy_from_slice(&digest[..8]);
    let h = u64::from_le_bytes(h_bytes);
    (h % (width as u64)) as usize
}

// ---------------------------------------------------------------------------
// Budget tracker
// ---------------------------------------------------------------------------

/// Fail-closed bandwidth + compute budget tracker.
///
/// One instance is constructed per aggregation round. Operations call
/// [`BudgetTracker::charge_bandwidth`] / [`BudgetTracker::charge_compute`]
/// **before** performing the work; if either returns `Err`, the caller MUST
/// abort the operation without mutating the sketch.
#[derive(Debug, Clone)]
pub struct BudgetTracker {
    bandwidth_cap: u64,
    bandwidth_used: u64,
    compute_cap: u64,
    compute_used: u64,
    /// Bounded event log (most-recent-N) for audit/triage.
    events: Vec<String>,
}

impl Default for BudgetTracker {
    fn default() -> Self {
        Self::new(DEFAULT_BANDWIDTH_BYTES, DEFAULT_COMPUTE_OPS)
    }
}

impl BudgetTracker {
    pub fn new(bandwidth_cap: u64, compute_cap: u64) -> Self {
        Self {
            bandwidth_cap,
            bandwidth_used: 0,
            compute_cap,
            compute_used: 0,
            events: Vec::new(),
        }
    }

    pub fn with_bandwidth(mut self, cap: u64) -> Self {
        self.bandwidth_cap = cap;
        self
    }

    pub fn with_compute(mut self, cap: u64) -> Self {
        self.compute_cap = cap;
        self
    }

    pub fn bandwidth_remaining(&self) -> u64 {
        self.bandwidth_cap.saturating_sub(self.bandwidth_used)
    }

    pub fn compute_remaining(&self) -> u64 {
        self.compute_cap.saturating_sub(self.compute_used)
    }

    pub fn events(&self) -> &[String] {
        &self.events
    }

    fn log(&mut self, msg: String) {
        push_bounded(&mut self.events, msg, MAX_BUDGET_EVENTS);
    }

    /// Pre-charge the bandwidth budget. Fails closed if the request would
    /// exceed the remaining budget.
    pub fn charge_bandwidth(&mut self, bytes: u64) -> SketchResult<()> {
        let remaining = self.bandwidth_remaining();
        if bytes > remaining {
            self.log(format!(
                "{}: requested={} remaining={}",
                event_codes::ERR_BANDWIDTH_EXCEEDED,
                bytes,
                remaining
            ));
            return Err(SketchError::BandwidthExceeded {
                requested: bytes,
                remaining,
            });
        }
        self.bandwidth_used = self.bandwidth_used.saturating_add(bytes);
        self.log(format!(
            "{}: bytes={} total={}",
            event_codes::BANDWIDTH_CONSUMED,
            bytes,
            self.bandwidth_used
        ));
        Ok(())
    }

    /// Pre-charge the compute budget.
    pub fn charge_compute(&mut self, ops: u64) -> SketchResult<()> {
        let remaining = self.compute_remaining();
        if ops > remaining {
            self.log(format!(
                "{}: requested={} remaining={}",
                event_codes::ERR_COMPUTE_EXCEEDED,
                ops,
                remaining
            ));
            return Err(SketchError::ComputeExceeded {
                requested: ops,
                remaining,
            });
        }
        self.compute_used = self.compute_used.saturating_add(ops);
        self.log(format!(
            "{}: ops={} total={}",
            event_codes::COMPUTE_CONSUMED,
            ops,
            self.compute_used
        ));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn small_cms() -> CountMinSketch {
        CountMinSketch::new(4, 64).expect("dims valid")
    }

    // INV-ATC-SKETCH-DETERMINISM
    #[test]
    fn deterministic_seed_derivation() {
        let a = CountMinSketch::new(5, 128).unwrap();
        let b = CountMinSketch::new(5, 128).unwrap();
        assert_eq!(a.hash_seeds, b.hash_seeds);
        assert_eq!(a.hash_seeds.len(), 5);
    }

    #[test]
    fn seeds_change_with_dimensions() {
        let a = CountMinSketch::new(5, 128).unwrap();
        let b = CountMinSketch::new(5, 256).unwrap();
        assert_ne!(a.hash_seeds, b.hash_seeds);
    }

    // INV-ATC-SKETCH-MERGE-COMMUTATIVE
    #[test]
    fn merge_is_commutative() {
        let mut left = small_cms();
        let mut right = small_cms();
        left.add(b"alpha", 3);
        left.add(b"beta", 7);
        right.add(b"alpha", 11);
        right.add(b"gamma", 5);

        let mut ab = left.clone();
        ab.merge(&right).unwrap();
        let mut ba = right.clone();
        ba.merge(&left).unwrap();
        assert_eq!(ab.table, ba.table);
        assert_eq!(ab.estimate(b"alpha"), ba.estimate(b"alpha"));
    }

    // INV-ATC-SKETCH-MERGE-ASSOCIATIVE
    #[test]
    fn merge_is_associative() {
        let mut a = small_cms();
        let mut b = small_cms();
        let mut c = small_cms();
        a.add(b"x", 2);
        b.add(b"y", 3);
        c.add(b"z", 5);

        // (a ∘ b) ∘ c
        let mut left = a.clone();
        left.merge(&b).unwrap();
        left.merge(&c).unwrap();
        // a ∘ (b ∘ c)
        let mut right = b.clone();
        right.merge(&c).unwrap();
        let mut combined = a.clone();
        combined.merge(&right).unwrap();
        assert_eq!(left.table, combined.table);
    }

    #[test]
    fn empty_sketch_merge_is_identity() {
        let mut populated = small_cms();
        populated.add(b"hello", 42);
        let empty = small_cms();

        let mut merged = populated.clone();
        merged.merge(&empty).unwrap();
        assert_eq!(merged.table, populated.table);

        let mut merged2 = empty.clone();
        merged2.merge(&populated).unwrap();
        assert_eq!(merged2.table, populated.table);
    }

    #[test]
    fn merge_dimension_mismatch_fails_closed() {
        let mut a = CountMinSketch::new(4, 64).unwrap();
        let b = CountMinSketch::new(5, 64).unwrap();
        let err = a.merge(&b).unwrap_err();
        assert!(matches!(err, SketchError::DimensionMismatch { .. }));
        assert!(format!("{err}").contains("ATC-SKETCH-ERR-001"));
    }

    #[test]
    fn invalid_dimensions_rejected() {
        assert!(matches!(
            CountMinSketch::new(0, 64).unwrap_err(),
            SketchError::InvalidDimensions { .. }
        ));
        assert!(matches!(
            CountMinSketch::new(4, 0).unwrap_err(),
            SketchError::InvalidDimensions { .. }
        ));
        assert!(matches!(
            CountMinSketch::new(MAX_CMS_DEPTH + 1, 64).unwrap_err(),
            SketchError::InvalidDimensions { .. }
        ));
        assert!(matches!(
            CountMinSketch::new(4, MAX_CMS_WIDTH + 1).unwrap_err(),
            SketchError::InvalidDimensions { .. }
        ));
    }

    // INV-ATC-SKETCH-OVERFLOW-SAFE
    #[test]
    fn saturating_add_overflow_safety() {
        let mut a = small_cms();
        // Push a single cell to u64::MAX directly through repeated huge adds.
        a.add(b"saturate-me", u64::MAX);
        a.add(b"saturate-me", u64::MAX);
        assert_eq!(a.estimate(b"saturate-me"), u64::MAX);

        // Merging two saturated sketches must not panic and must stay capped.
        let mut b = a.clone();
        b.merge(&a).unwrap();
        assert_eq!(b.estimate(b"saturate-me"), u64::MAX);
    }

    // INV-ATC-SKETCH-ERROR-BOUND
    #[test]
    fn error_bound_math_matches_theory() {
        let bound = compute_error_bound(7, 2719).unwrap(); // ceil(e*1000)
        // ε ≈ e/w = 2.718.../2719 ≈ 0.001
        assert!((bound.eps - std::f64::consts::E / 2719.0).abs() < 1e-12);
        // δ = e^{-d}
        assert!((bound.delta - (-7.0_f64).exp()).abs() < 1e-12);
        // confidence_pct in [0, 100]
        let conf = bound.confidence_pct();
        assert!((0.0..=100.0).contains(&conf));
    }

    #[test]
    fn error_bound_finite_guards() {
        // depth=0 / width=0 fail closed.
        assert!(compute_error_bound(0, 64).is_err());
        assert!(compute_error_bound(4, 0).is_err());
        // Out-of-cap fail closed.
        assert!(compute_error_bound(MAX_CMS_DEPTH + 1, 64).is_err());

        // for_bounds NaN/inf rejection.
        assert!(CountMinSketch::for_bounds(f64::NAN, 0.01).is_err());
        assert!(CountMinSketch::for_bounds(0.01, f64::INFINITY).is_err());
        assert!(CountMinSketch::for_bounds(-0.5, 0.01).is_err());
        assert!(CountMinSketch::for_bounds(0.01, 2.0).is_err());
    }

    #[test]
    fn for_bounds_picks_reasonable_dimensions() {
        let s = CountMinSketch::for_bounds(0.01, 0.01).unwrap();
        assert!(s.width() >= (std::f64::consts::E / 0.01).ceil() as u32);
        assert!(s.depth() >= 1);
        assert!(s.depth() <= MAX_CMS_DEPTH);
    }

    #[test]
    fn estimate_lower_bounds_true_count_with_high_probability() {
        // CMS is *biased upward*: estimate(x) >= true_count(x) always.
        let mut s = CountMinSketch::for_bounds(0.05, 0.05).unwrap();
        for i in 0..500u32 {
            s.insert(format!("item-{i}").as_bytes());
        }
        let true_count = 1u64;
        let est = s.estimate(b"item-42");
        assert!(est >= true_count, "estimate {est} < true {true_count}");
    }

    // INV-ATC-SKETCH-DETERMINISM (serialization)
    #[test]
    fn serialization_round_trip_preserves_estimates() {
        let mut s = small_cms();
        for i in 0..20u32 {
            s.insert(format!("k{i}").as_bytes());
        }
        let bytes = serde_json::to_vec(&s).unwrap();
        let parsed: CountMinSketch = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.depth, s.depth);
        assert_eq!(parsed.width, s.width);
        assert_eq!(parsed.table, s.table);
        assert_eq!(parsed.hash_seeds, s.hash_seeds);
        for i in 0..20u32 {
            let key = format!("k{i}");
            assert_eq!(parsed.estimate(key.as_bytes()), s.estimate(key.as_bytes()));
        }
    }

    #[test]
    fn serialized_size_matches_layout_formula() {
        let s = CountMinSketch::new(4, 64).unwrap();
        let expected = 8 + 4 * 8 + 4 * 64 * 8;
        assert_eq!(s.serialized_size(), expected);
    }

    // INV-ATC-SKETCH-BUDGET-ENFORCED (bandwidth)
    #[test]
    fn bandwidth_budget_caps_serialization() {
        let s = CountMinSketch::new(4, 64).unwrap();
        let bytes = s.serialized_size() as u64;
        // Cap fits exactly one sketch; the second charge must fail closed.
        let mut tracker = BudgetTracker::new(bytes, DEFAULT_COMPUTE_OPS);
        assert!(tracker.charge_bandwidth(bytes).is_ok());
        let err = tracker.charge_bandwidth(bytes).unwrap_err();
        assert!(matches!(err, SketchError::BandwidthExceeded { .. }));
        assert!(format!("{err}").contains("ATC-SKETCH-ERR-002"));
        assert!(tracker.events().iter().any(|e| e.contains("ERR-002")));
    }

    // INV-ATC-SKETCH-BUDGET-ENFORCED (compute)
    #[test]
    fn compute_budget_caps_insertions() {
        let mut tracker = BudgetTracker::new(DEFAULT_BANDWIDTH_BYTES, 100);
        // 100 inserts fit; 101st must fail.
        for _ in 0..100 {
            tracker.charge_compute(1).unwrap();
        }
        let err = tracker.charge_compute(1).unwrap_err();
        assert!(matches!(err, SketchError::ComputeExceeded { .. }));
        assert_eq!(tracker.compute_remaining(), 0);
    }

    #[test]
    fn budget_tracker_event_log_is_bounded() {
        let mut tracker = BudgetTracker::new(u64::MAX, u64::MAX);
        for _ in 0..(MAX_BUDGET_EVENTS + 200) {
            tracker.charge_compute(1).unwrap();
        }
        assert!(tracker.events().len() <= MAX_BUDGET_EVENTS);
    }

    // Large-N merge: 1000 participants each contribute small populated CMS;
    // verify merge is total + deterministic + bandwidth-respecting.
    #[test]
    fn merge_scales_to_many_participants_under_budget() {
        let n_participants = 1000u32;
        let mut global = CountMinSketch::new(4, 256).unwrap();
        let per_size = global.serialized_size() as u64;
        let bandwidth_cap = per_size.saturating_mul(n_participants as u64);
        let mut tracker =
            BudgetTracker::new(bandwidth_cap, (n_participants as u64).saturating_mul(50));
        for p in 0..n_participants {
            tracker.charge_bandwidth(per_size).unwrap();
            tracker.charge_compute(10).unwrap();
            let mut local = CountMinSketch::new(4, 256).unwrap();
            local.insert(format!("attacker-{}", p % 50).as_bytes());
            global.merge(&local).unwrap();
        }
        let est = global.estimate(b"attacker-7");
        assert!(est >= 20, "estimate {est} < expected 20");
        assert_eq!(tracker.bandwidth_remaining(), 0);
    }

    #[test]
    fn cell_column_distribution_in_range() {
        let seeds = derive_hash_seeds(4, 100);
        for s in seeds {
            for k in 0..50u32 {
                let key = format!("k{k}");
                let col = cell_column(s, key.as_bytes(), 100);
                assert!(col < 100);
            }
        }
    }

    #[test]
    fn add_zero_count_is_noop() {
        let mut s = small_cms();
        let before = s.table.clone();
        s.add(b"x", 0);
        assert_eq!(s.table, before);
        assert_eq!(s.estimate(b"x"), 0);
    }

    #[test]
    fn estimate_is_zero_on_unknown_key() {
        let s = small_cms();
        assert_eq!(s.estimate(b"never-inserted"), 0);
    }

    #[test]
    fn error_bound_confidence_pct_in_range() {
        // delta=1 → confidence 0; delta near 0 → confidence near 100.
        let high = ErrorBound {
            eps: 0.01,
            delta: 1e-9,
        };
        let low = ErrorBound {
            eps: 0.01,
            delta: 0.999,
        };
        let conf_high = high.confidence_pct();
        let conf_low = low.confidence_pct();
        assert!(conf_high > conf_low);
        assert!((0.0..=100.0).contains(&conf_high));
        assert!((0.0..=100.0).contains(&conf_low));
    }

    // Frozen u64 outputs of TWO module-private hashing functions in
    // this file:
    //
    //   derive_hash_seeds (atc_sketches.rs:514):
    //     For each row in [0, depth):
    //       seed = u64::from_le_bytes(SHA256(
    //         LE64(len(CMS_DOMAIN_SEPARATOR))
    //         || CMS_DOMAIN_SEPARATOR
    //         || depth.to_le_bytes()     # u32 LE — 4 bytes (NOT 8!)
    //         || width.to_le_bytes()     # u32 LE
    //         || row.to_le_bytes()       # u32 LE
    //       ).finalize()[..8])
    //
    //   cell_column (atc_sketches.rs:533):
    //     If width == 0: return 0
    //     h = u64::from_le_bytes(SHA256(
    //       LE64(len(CMS_DOMAIN_SEPARATOR))
    //       || CMS_DOMAIN_SEPARATOR
    //       || seed.to_le_bytes()        # u64 LE — 8 bytes
    //       || LE64(len(key)) || key
    //     ).finalize()[..8])
    //     return (h % width as u64) as usize
    //
    // Where CMS_DOMAIN_SEPARATOR = b"atc_sketch_cms_v1:" (18 bytes).
    //
    // *** TWO DISTINCTIVE FEATURES (FIRSTS in suite) ***
    //
    // 1. u32-LE ENCODING FOR DIMENSIONS: this is the FIRST golden to
    //    pin u32-LE encoding (4 bytes) for the depth/width/row fields
    //    of derive_hash_seeds. Every prior golden in the suite has
    //    used u64-LE (8 bytes) for counter fields. A future refactor
    //    that "widened all counters to u64" would silently double the
    //    bytes-per-counter AND flip every existing seed across the
    //    sketch fleet. The two prior u32-vs-u64-width-contract goldens
    //    (r55 incident_bundle_retention's export_format_version,
    //    r66 here) document the u32 contract on different surfaces.
    //
    // 2. SHA256-TRUNCATE-TO-u64 PATTERN: both functions take the
    //    first 8 bytes of the SHA-256 digest and interpret as u64
    //    via from_le_bytes. This is a load-bearing decision (only
    //    8 of the 32 SHA-256 bytes contribute to the seed/column);
    //    a refactor to take a different slice (e.g., bytes 8..16) or
    //    use a different endianness would silently shift every
    //    sketch column mapping.
    //
    // Five frozen fixtures + three structural invariants:
    //
    // derive_hash_seeds:
    //   1. depth=1, width=16 → single seed 0x294655db40e9a76c.
    //   2. depth=3, width=256 → three seeds
    //      [0xe57d966d5f352fe2, 0x83adbca9a72f2d10, 0xe06836c440838296].
    //
    // cell_column:
    //   3. seed=0x1234567890abcdef, key=b"", width=1 → 0
    //      (any value mod 1 is 0 — locks the width=1 edge case).
    //   4. seed=0x1234567890abcdef, key=b"hello", width=1024 → 199.
    //   5. seed=0, key=b"\0", width=100 → 86.
    //
    //   6. WIDTH-ZERO-EARLY-RETURN: cell_column(_, _, 0) MUST return
    //      0 without dividing (catches a refactor that removed the
    //      early-return guard, which would cause divide-by-zero
    //      panic).
    //
    //   7. SEED-DETERMINATION INVARIANT: derive_hash_seeds(d, w)
    //      MUST produce d seeds where each is determined by
    //      (depth, width, row) — changing only depth or width MUST
    //      flip ALL seeds in the vector.
    //
    //   8. KEY-IN-COLUMN INVARIANT: same seed + same width + different
    //      key MUST produce (likely) different column. Tests that the
    //      key contributes to the hash.
    //
    // Goldens were derived offline from the canonical-byte spec via
    // Python (struct.pack('<I', ...) for u32 LE, '<Q' for u64 LE) —
    // NOT captured from an unreviewed prior run.
    //
    // Why this matters (the contract): derive_hash_seeds + cell_column
    // together form the Count-Min Sketch row/column mapping for ATC
    // federation. If two aggregators compute different seeds or
    // columns for the same logical (depth, width, row, seed, key)
    // tuple — because someone widened u32 to u64, dropped the
    // truncate-to-first-8-bytes pattern, or muddled the v1 domain —
    // CMS estimates diverge across the federation AND the sketch
    // becomes nondeterministic.
    #[test]
    fn atc_sketches_hash_primitives_frozen_canonical_byte_layout_golden() {
        // 1. derive_hash_seeds(depth=1, width=16): single seed.
        let seeds_1x16 = super::derive_hash_seeds(1, 16);
        assert_eq!(
            seeds_1x16,
            vec![0x294655db40e9a76c_u64],
            "derive_hash_seeds(1, 16) drifted — check the CMS_DOMAIN_\
             SEPARATOR (b\"atc_sketch_cms_v1:\"), the u32-LE encoding \
             of depth/width/row (4 bytes each), OR the SHA256-truncate-\
             to-first-8-bytes-as-u64-LE pattern"
        );

        // 2. derive_hash_seeds(depth=3, width=256): three seeds.
        let seeds_3x256 = super::derive_hash_seeds(3, 256);
        assert_eq!(
            seeds_3x256,
            vec![
                0xe57d966d5f352fe2_u64,
                0x83adbca9a72f2d10_u64,
                0xe06836c440838296_u64,
            ],
            "derive_hash_seeds(3, 256) drifted — three rows of seeds \
             MUST be derived in row-iteration order with row.to_le_bytes() \
             (u32 LE) as the per-row salt"
        );

        // 3. cell_column width-zero edge case.
        assert_eq!(
            super::cell_column(0x1234567890abcdef, b"", 1),
            0,
            "cell_column(_, _, 1) MUST return 0 (any value mod 1 is 0)"
        );

        // 4. cell_column with non-empty key.
        assert_eq!(
            super::cell_column(0x1234567890abcdef, b"hello", 1024),
            199,
            "cell_column drifted — check CMS_DOMAIN_SEPARATOR, seed \
             u64-LE encoding, OR LE64-len-prefix on key"
        );

        // 5. cell_column with binary key + seed=0.
        assert_eq!(
            super::cell_column(0, b"\0", 100),
            86,
            "cell_column with seed=0 and single null byte key drifted \
             — pins that seed=0 is fed as 8 zero bytes (NOT skipped)"
        );

        // 6. WIDTH-ZERO-EARLY-RETURN INVARIANT.
        assert_eq!(
            super::cell_column(0x1234567890abcdef, b"any-key", 0),
            0,
            "cell_column(_, _, 0) MUST return 0 via the early-return \
             guard at L534 (catches a refactor that removed the guard, \
             which would cause divide-by-zero panic)"
        );

        // 7. SEED-DETERMINATION INVARIANT: depth-bumped seeds MUST
        // differ entirely from the original. Each seed depends on
        // (depth, width, row); changing depth changes ALL seeds.
        let seeds_2x16 = super::derive_hash_seeds(2, 16);
        // The first seed at depth=2 must differ from the first seed
        // at depth=1 (because depth field changed).
        assert_ne!(
            seeds_2x16[0], seeds_1x16[0],
            "derive_hash_seeds(2, 16)[0] MUST differ from \
             derive_hash_seeds(1, 16)[0] — depth IS fed into each \
             per-row hash, so changing depth flips all seeds"
        );

        // 8. KEY-IN-COLUMN INVARIANT: same seed/width + different key
        // produces different column (with high probability — using
        // two distinct keys here).
        let col_a = super::cell_column(0xDEADBEEF, b"key-a", 65536);
        let col_b = super::cell_column(0xDEADBEEF, b"key-b", 65536);
        assert_ne!(
            col_a, col_b,
            "different keys with same seed+width MUST produce \
             different columns (assuming reasonable hash distribution); \
             if equal here, the key may not be feeding into the hasher"
        );

        // Seeds length contract: derive_hash_seeds(depth, _) returns
        // exactly `depth` seeds.
        assert_eq!(seeds_1x16.len(), 1);
        assert_eq!(seeds_3x256.len(), 3);
        assert_eq!(seeds_2x16.len(), 2);
    }
}
