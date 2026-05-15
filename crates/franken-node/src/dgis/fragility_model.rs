//! Maintainer / publisher fragility model and single-point-of-failure (SPOF) types.
//!
//! This module defines the type foundation for bd-2jns (sub-task 1 of 5).
//! It contains the data shapes that the downstream SPOF detector, severity
//! classifier, and verification gate will consume:
//!
//! * [`MaintainerProfile`] — per-maintainer ownership and recovery state.
//! * [`PublisherProfile`] — per-publisher signing/quorum metadata.
//! * [`FragilityFactor`] — the discrete reasons a profile may be classified
//!   as fragile (sole-maintainer, no-key-recovery, stale, orphaned package,
//!   unrotated key, no quorum, concentrated downloads).
//! * [`FragilityScore`] — a normalized [0.0, 1.0] severity score plus the
//!   contributing factors and the maximum-severity factor, suitable for the
//!   structured findings output described in the bd-2jns spec.
//!
//! Two `assess_*` functions translate a profile + a wall-clock instant into
//! a `FragilityScore`. Each function validates inputs (non-empty ids, finite
//! `f64` shares, monotonic timestamps) and surfaces failures as a typed
//! [`FragilityError`] rather than silently returning a degenerate score.
//!
//! Hardening conventions applied here:
//!
//! * All `f64` field values are guarded with `is_finite()` before
//!   serialization or accumulation.
//! * Staleness day computation uses `saturating_sub` on `i64` deltas to
//!   prevent overflow when `last_commit_ts` is in the future.
//! * Length-prefixed canonical encoding is used for the deterministic hash
//!   helper so concatenated string fields cannot collide via delimiter
//!   smuggling.
//! * `push_bounded` is used when accumulating contributing factors so a
//!   pathological profile cannot exhaust memory.
//!
//! NB: this sub-task ships ONLY the type foundation + inline round-trip and
//! assessment tests. The actual SPOF graph traversal, fixture suite,
//! integration test, and verification gate are tracked as sub-tasks 2–5 of
//! bd-2jns.1.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;

// ---------------------------------------------------------------------------
// Tunable thresholds
// ---------------------------------------------------------------------------

/// Bus factor at or below which a maintainer is treated as a sole-maintainer
/// single-point-of-failure. A bus factor of zero or one means there is at
/// most one human capable of merging changes; either case is fragile.
pub const SOLE_MAINTAINER_BUS_FACTOR: u8 = 1;

/// Number of days since last commit beyond which a maintainer is considered
/// "stale". One calendar year matches the supply-chain audit literature
/// (xz-utils retrospective et al.) without flagging routine summer breaks.
pub const STALE_MAINTAINER_DAYS: u32 = 365;

/// Key rotation policy age (in days) above which a publisher's signing key
/// is treated as "unrotated" by default. This is a model parameter — the
/// concrete value here is just the inline-test default; the SPOF detector
/// in sub-task 2 will accept a per-publisher override.
pub const DEFAULT_UNROTATED_KEY_DAYS: u32 = 730;

/// Download concentration share (per-maintainer percentage of an
/// ecosystem's total monthly downloads) at or above which the profile is
/// flagged as `ConcentratedDownloads`. 0.05 = 5%.
pub const CONCENTRATED_DOWNLOADS_SHARE: f64 = 0.05;

/// Maximum number of fragility factors that may accumulate in a single
/// `FragilityScore`. Bounded so a misuse cannot exhaust memory.
pub const MAX_FRAGILITY_FACTORS: usize = MAX_AUDIT_LOG_ENTRIES;

// Compile-time guard: the concentrated-downloads default share must be a
// finite, in-range probability. Because const fns cannot call `is_finite`
// directly on stable, we rely on the inline equality check.
const _: () = assert!(
    CONCENTRATED_DOWNLOADS_SHARE > 0.0 && CONCENTRATED_DOWNLOADS_SHARE < 1.0,
    "concentrated downloads share must be a strict probability"
);

const _: () = assert!(
    STALE_MAINTAINER_DAYS > 0,
    "stale maintainer days must be positive"
);

const _: () = assert!(
    DEFAULT_UNROTATED_KEY_DAYS >= STALE_MAINTAINER_DAYS,
    "unrotated key days must be at least stale maintainer days",
);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that the fragility model can surface.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FragilityError {
    /// Maintainer / publisher ID was empty or whitespace-only.
    #[error("identifier is empty")]
    EmptyIdentifier,
    /// A floating-point field carried NaN or ±infinity.
    #[error("non-finite floating point value in field '{field}'")]
    NonFiniteValue { field: &'static str },
    /// A floating-point share was outside the [0.0, 1.0] interval.
    #[error("share value out of range in field '{field}': value={value}")]
    ShareOutOfRange { field: &'static str, value: String },
    /// `now` predates `active_since` for a maintainer, which is unsupported.
    #[error("clock skew: now ({now}) precedes active_since ({active_since})")]
    ClockSkew { now: i64, active_since: i64 },
}

/// Convenience `Result` alias for fragility-model operations.
pub type Result<T> = std::result::Result<T, FragilityError>;

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

/// A summary of a single maintainer's footprint within the dependency graph.
///
/// All collection fields are stable-ordered (Vec, not HashSet) to keep
/// downstream canonical encoding deterministic. `id` must be non-empty;
/// `bus_factor` is intentionally a `u8` because human teams large enough to
/// exceed 255 active maintainers are rare in the supply-chain domain and
/// the smaller type prevents accidental scaling-up to graph-sized counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintainerProfile {
    /// Stable identifier (e.g. GitHub login, GPG key fingerprint).
    pub id: String,
    /// Packages this maintainer is listed as a code-owner for.
    pub packages_owned: Vec<String>,
    /// Aggregate monthly downloads across `packages_owned`.
    pub total_downloads_per_month: u64,
    /// Whether the maintainer has documented key-recovery procedures.
    pub key_recovery_setup: bool,
    /// Unix-epoch seconds at which the maintainer became active.
    pub active_since: i64,
    /// Optional Unix-epoch seconds of last observed commit.
    pub last_commit_ts: Option<i64>,
    /// Heuristic bus factor: the minimum number of departures that would
    /// orphan all owned packages.
    pub bus_factor: u8,
}

impl MaintainerProfile {
    /// Validate invariants that are too rich to express in the type system.
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(FragilityError::EmptyIdentifier);
        }
        Ok(())
    }
}

/// A summary of a single publishing identity's release / signing footprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherProfile {
    /// Stable identifier (e.g. crates.io account, npm scope).
    pub id: String,
    /// Optional parent organization identifier.
    pub org_id: Option<String>,
    /// Packages published under this identity.
    pub packages_published: Vec<String>,
    /// Number of distinct signing keys currently configured.
    pub signature_keys_count: u32,
    /// Optional opaque policy descriptor (e.g. "rotate-90d", "manual").
    pub key_rotation_policy: Option<String>,
    /// Optional `m` value of an `m-of-n` recovery quorum, if any.
    pub recovery_quorum: Option<u8>,
}

impl PublisherProfile {
    /// Validate invariants that are too rich to express in the type system.
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(FragilityError::EmptyIdentifier);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fragility factor & score
// ---------------------------------------------------------------------------

/// A discrete fragility signal contributing to a [`FragilityScore`].
///
/// `Eq` is intentionally NOT derived because `ConcentratedDownloads`
/// contains a non-`Eq` `f64`. `PartialEq` is sufficient for the inline tests
/// and for the downstream classifier in sub-task 2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FragilityFactor {
    /// Maintainer owns one or more packages with `bus_factor <= 1`.
    SingleMaintainer,
    /// Maintainer has no documented key-recovery procedure.
    NoKeyRecovery,
    /// Maintainer last committed more than `staleness_days` ago.
    StaleMaintainer { staleness_days: u32 },
    /// Package has zero current maintainers.
    OrphanedPackage,
    /// Publisher signing key has not been rotated within `age_days`.
    UnrotatedKey { age_days: u32 },
    /// Publisher has no `m-of-n` recovery quorum (or `m = 1`).
    NoQuorum,
    /// Maintainer's `share` of ecosystem downloads is concentrated above the
    /// configured threshold; `share` is finite and in `[0.0, 1.0]`.
    ConcentratedDownloads { share: f64 },
}

impl FragilityFactor {
    /// Weight assigned to this factor when accumulating a normalized score
    /// in `[0.0, 1.0]`. Weights are deliberately additive (capped to 1.0)
    /// rather than multiplicative so the score is monotonic in the number
    /// of contributing signals.
    pub fn weight(&self) -> f64 {
        match self {
            Self::SingleMaintainer => 0.35,
            Self::NoKeyRecovery => 0.20,
            Self::StaleMaintainer { .. } => 0.15,
            Self::OrphanedPackage => 0.30,
            Self::UnrotatedKey { .. } => 0.15,
            Self::NoQuorum => 0.20,
            Self::ConcentratedDownloads { .. } => 0.25,
        }
    }

    /// Severity ordering used to compute `FragilityScore::max_factor`.
    /// Higher numbers mean more severe.
    pub fn severity_rank(&self) -> u8 {
        match self {
            Self::SingleMaintainer => 4,
            Self::OrphanedPackage => 4,
            Self::ConcentratedDownloads { .. } => 3,
            Self::NoKeyRecovery => 3,
            Self::NoQuorum => 3,
            Self::UnrotatedKey { .. } => 2,
            Self::StaleMaintainer { .. } => 2,
        }
    }

    /// Stable string label for telemetry / log codes.
    pub fn label(&self) -> &'static str {
        match self {
            Self::SingleMaintainer => "single_maintainer",
            Self::NoKeyRecovery => "no_key_recovery",
            Self::StaleMaintainer { .. } => "stale_maintainer",
            Self::OrphanedPackage => "orphaned_package",
            Self::UnrotatedKey { .. } => "unrotated_key",
            Self::NoQuorum => "no_quorum",
            Self::ConcentratedDownloads { .. } => "concentrated_downloads",
        }
    }
}

/// The output of a fragility assessment.
///
/// `total` is clamped to `[0.0, 1.0]`. `factors` is bounded by
/// `MAX_FRAGILITY_FACTORS`. `max_factor` is the contributor with the highest
/// `severity_rank` (ties broken by insertion order), and is `None` only when
/// `factors` is empty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FragilityScore {
    /// Normalized score in `[0.0, 1.0]`, higher means more fragile.
    pub total: f64,
    /// Contributing factors in insertion order.
    pub factors: Vec<FragilityFactor>,
    /// Highest-severity contributing factor, if any.
    pub max_factor: Option<FragilityFactor>,
    /// Unix-epoch seconds at which this score was computed.
    pub computed_at: i64,
}

impl FragilityScore {
    /// Construct an empty (non-fragile) score at `now`.
    pub fn empty(now: i64) -> Self {
        Self {
            total: 0.0,
            factors: Vec::new(),
            max_factor: None,
            computed_at: now,
        }
    }

    /// Whether any contributing factor was found.
    pub fn is_fragile(&self) -> bool {
        !self.factors.is_empty()
    }

    /// Deterministic length-prefixed content hash used for downstream
    /// fingerprinting of fragility findings. Domain-separated with
    /// `b"dgis_fragility_v1:"` to prevent cross-module collisions.
    pub fn content_hash(&self) -> std::result::Result<String, serde_json::Error> {
        let canonical = serde_json::to_string(self)?;
        let mut hasher = Sha256::new();
        hasher.update(b"dgis_fragility_v1:");
        // Length-prefix the canonical payload to defeat delimiter smuggling.
        hasher.update(len_to_u64(canonical.len()).to_le_bytes());
        hasher.update(canonical.as_bytes());
        let digest = hasher.finalize();
        Ok(hex::encode(digest))
    }
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// Internal accumulator
// ---------------------------------------------------------------------------

/// Lightweight builder that the `assess_*` functions use to accumulate
/// factors with bounded capacity, then materialize a `FragilityScore`.
#[derive(Debug)]
struct Accumulator {
    factors: Vec<FragilityFactor>,
}

impl Accumulator {
    fn new() -> Self {
        Self {
            factors: Vec::new(),
        }
    }

    fn add(&mut self, factor: FragilityFactor) {
        push_bounded(&mut self.factors, factor, MAX_FRAGILITY_FACTORS);
    }

    fn finalize(self, now: i64) -> FragilityScore {
        let mut total = 0.0_f64;
        let mut max_factor: Option<FragilityFactor> = None;

        for factor in &self.factors {
            let w = factor.weight();
            // Each weight is documented as finite & non-negative, but guard
            // anyway so a future edit cannot poison the sum.
            if w.is_finite() && w > 0.0 {
                total += w;
            }
            let take = match &max_factor {
                None => true,
                Some(current) => factor.severity_rank() > current.severity_rank(),
            };
            if take {
                max_factor = Some(factor.clone());
            }
        }

        if !total.is_finite() {
            total = 0.0;
        }
        if total > 1.0 {
            total = 1.0;
        }
        if total < 0.0 {
            total = 0.0;
        }

        FragilityScore {
            total,
            factors: self.factors,
            max_factor,
            computed_at: now,
        }
    }
}

// ---------------------------------------------------------------------------
// Assessment entry points
// ---------------------------------------------------------------------------

/// Assess the fragility of a single maintainer at wall-clock `now`.
///
/// Returns `Ok(FragilityScore)` even when the maintainer is non-fragile;
/// callers should consult `score.is_fragile()` rather than treating
/// `Ok(...)` as "fragility detected".
pub fn assess_maintainer(profile: &MaintainerProfile, now: i64) -> Result<FragilityScore> {
    profile.validate()?;

    if now < profile.active_since {
        return Err(FragilityError::ClockSkew {
            now,
            active_since: profile.active_since,
        });
    }

    let mut acc = Accumulator::new();

    if profile.bus_factor <= SOLE_MAINTAINER_BUS_FACTOR {
        acc.add(FragilityFactor::SingleMaintainer);
    }

    if !profile.key_recovery_setup {
        acc.add(FragilityFactor::NoKeyRecovery);
    }

    if let Some(last_commit) = profile.last_commit_ts {
        // saturating_sub on i64 prevents overflow if last_commit is in the
        // future (clock skew on the caller side).
        let delta_secs = now.saturating_sub(last_commit);
        if delta_secs > 0 {
            // i64 -> u32 days: safe because we cap at u32::MAX. One day = 86400s.
            let days = (delta_secs as u64) / 86_400;
            let days_u32 = u32::try_from(days).unwrap_or(u32::MAX);
            if days_u32 > STALE_MAINTAINER_DAYS {
                acc.add(FragilityFactor::StaleMaintainer {
                    staleness_days: days_u32,
                });
            }
        }
    }

    Ok(acc.finalize(now))
}

/// Assess the fragility of a single publisher at wall-clock `now`.
pub fn assess_publisher(profile: &PublisherProfile, now: i64) -> Result<FragilityScore> {
    profile.validate()?;

    let mut acc = Accumulator::new();

    if profile.key_rotation_policy.is_none() {
        acc.add(FragilityFactor::UnrotatedKey {
            age_days: DEFAULT_UNROTATED_KEY_DAYS,
        });
    }

    // Treat missing quorum AND single-signer quorum as fragile.
    match profile.recovery_quorum {
        None => acc.add(FragilityFactor::NoQuorum),
        Some(m) if m <= 1 => acc.add(FragilityFactor::NoQuorum),
        Some(_) => {}
    }

    if profile.packages_published.is_empty() {
        // A publisher with zero published packages is, by definition,
        // orphaned from the supply-chain perspective.
        acc.add(FragilityFactor::OrphanedPackage);
    }

    Ok(acc.finalize(now))
}

/// Construct a `ConcentratedDownloads` factor with a `share` that is
/// validated to be finite and in `[0.0, 1.0]`. Callers MUST use this helper
/// rather than constructing the variant directly when the `share` is
/// derived from untrusted data.
pub fn concentrated_downloads_factor(share: f64) -> Result<FragilityFactor> {
    if !share.is_finite() {
        return Err(FragilityError::NonFiniteValue { field: "share" });
    }
    if !(0.0..=1.0).contains(&share) {
        return Err(FragilityError::ShareOutOfRange {
            field: "share",
            value: format!("{}", share),
        });
    }
    Ok(FragilityFactor::ConcentratedDownloads { share })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_maintainer() -> MaintainerProfile {
        MaintainerProfile {
            id: "alice".to_string(),
            packages_owned: vec!["pkg-a".to_string(), "pkg-b".to_string()],
            total_downloads_per_month: 1_000_000,
            key_recovery_setup: true,
            active_since: 1_000_000_000,
            last_commit_ts: Some(1_700_000_000),
            bus_factor: 5,
        }
    }

    fn sample_publisher() -> PublisherProfile {
        PublisherProfile {
            id: "acme-publisher".to_string(),
            org_id: Some("acme".to_string()),
            packages_published: vec!["pkg-a".to_string()],
            signature_keys_count: 3,
            key_rotation_policy: Some("rotate-90d".to_string()),
            recovery_quorum: Some(3),
        }
    }

    #[test]
    fn maintainer_profile_round_trip_serde() {
        let original = sample_maintainer();
        let json = serde_json::to_string(&original).expect("serialize");
        let back: MaintainerProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, back);
    }

    #[test]
    fn publisher_profile_round_trip_serde() {
        let original = sample_publisher();
        let json = serde_json::to_string(&original).expect("serialize");
        let back: PublisherProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, back);
    }

    #[test]
    fn fragility_score_round_trip_serde() {
        let score = FragilityScore {
            total: 0.55,
            factors: vec![
                FragilityFactor::SingleMaintainer,
                FragilityFactor::StaleMaintainer {
                    staleness_days: 400,
                },
                FragilityFactor::ConcentratedDownloads { share: 0.42 },
            ],
            max_factor: Some(FragilityFactor::SingleMaintainer),
            computed_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&score).expect("serialize");
        let back: FragilityScore = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(score, back);
    }

    #[test]
    fn assess_maintainer_flags_bus_factor_one_as_single_maintainer() {
        let mut profile = sample_maintainer();
        profile.bus_factor = 1;
        let score = assess_maintainer(&profile, 1_800_000_000).expect("assess");
        assert!(
            score.factors.contains(&FragilityFactor::SingleMaintainer),
            "expected SingleMaintainer, got {:?}",
            score.factors
        );
        assert!(score.is_fragile());
    }

    #[test]
    fn assess_maintainer_flags_no_key_recovery() {
        let mut profile = sample_maintainer();
        profile.key_recovery_setup = false;
        let score = assess_maintainer(&profile, 1_800_000_000).expect("assess");
        assert!(score.factors.contains(&FragilityFactor::NoKeyRecovery));
    }

    #[test]
    fn assess_maintainer_flags_stale_maintainer_after_one_year() {
        let mut profile = sample_maintainer();
        // last commit 500 days before `now`.
        let now = 1_800_000_000_i64;
        profile.last_commit_ts = Some(now - 500 * 86_400);
        let score = assess_maintainer(&profile, now).expect("assess");
        let staleness = score
            .factors
            .iter()
            .find_map(|f| match f {
                FragilityFactor::StaleMaintainer { staleness_days } => Some(*staleness_days),
                _ => None,
            })
            .expect("should contain StaleMaintainer");
        assert_eq!(staleness, 500);
    }

    #[test]
    fn assess_maintainer_does_not_flag_recent_commit() {
        let mut profile = sample_maintainer();
        let now = 1_800_000_000_i64;
        // 30 days old → not stale.
        profile.last_commit_ts = Some(now - 30 * 86_400);
        let score = assess_maintainer(&profile, now).expect("assess");
        let any_stale = score
            .factors
            .iter()
            .any(|f| matches!(f, FragilityFactor::StaleMaintainer { .. }));
        assert!(!any_stale, "should not flag a 30-day-old commit");
    }

    #[test]
    fn assess_maintainer_handles_future_commit_with_saturating_sub() {
        // last_commit_ts in the future: saturating_sub yields 0, so no
        // staleness factor is added and no panic occurs.
        let mut profile = sample_maintainer();
        let now = 1_800_000_000_i64;
        profile.last_commit_ts = Some(now + 1000);
        let score = assess_maintainer(&profile, now).expect("assess");
        let any_stale = score
            .factors
            .iter()
            .any(|f| matches!(f, FragilityFactor::StaleMaintainer { .. }));
        assert!(!any_stale, "future commit must not be flagged as stale");
    }

    #[test]
    fn assess_publisher_flags_missing_key_rotation() {
        let mut profile = sample_publisher();
        profile.key_rotation_policy = None;
        let score = assess_publisher(&profile, 1_800_000_000).expect("assess");
        let any_unrotated = score
            .factors
            .iter()
            .any(|f| matches!(f, FragilityFactor::UnrotatedKey { .. }));
        assert!(any_unrotated, "missing rotation policy must flag");
    }

    #[test]
    fn assess_publisher_flags_missing_recovery_quorum() {
        let mut profile = sample_publisher();
        profile.recovery_quorum = None;
        let score = assess_publisher(&profile, 1_800_000_000).expect("assess");
        assert!(score.factors.contains(&FragilityFactor::NoQuorum));
    }

    #[test]
    fn assess_publisher_flags_single_signer_quorum_as_no_quorum() {
        let mut profile = sample_publisher();
        profile.recovery_quorum = Some(1);
        let score = assess_publisher(&profile, 1_800_000_000).expect("assess");
        assert!(score.factors.contains(&FragilityFactor::NoQuorum));
    }

    #[test]
    fn concentrated_downloads_rejects_nan_share() {
        let err = concentrated_downloads_factor(f64::NAN).expect_err("NaN must be rejected");
        assert_eq!(err, FragilityError::NonFiniteValue { field: "share" });
    }

    #[test]
    fn concentrated_downloads_rejects_infinity() {
        let err =
            concentrated_downloads_factor(f64::INFINITY).expect_err("infinity must be rejected");
        assert_eq!(err, FragilityError::NonFiniteValue { field: "share" });
    }

    #[test]
    fn concentrated_downloads_rejects_out_of_range() {
        let err = concentrated_downloads_factor(1.5).expect_err("share > 1.0 must be rejected");
        match err {
            FragilityError::ShareOutOfRange { field, .. } => assert_eq!(field, "share"),
            other => panic!("expected ShareOutOfRange, got {:?}", other),
        }
    }

    #[test]
    fn concentrated_downloads_accepts_valid_share() {
        let factor = concentrated_downloads_factor(0.42).expect("valid share");
        match factor {
            FragilityFactor::ConcentratedDownloads { share } => {
                assert!(share.is_finite());
                assert!((0.0..=1.0).contains(&share));
            }
            other => panic!("expected ConcentratedDownloads, got {:?}", other),
        }
    }

    #[test]
    fn empty_maintainer_id_rejected() {
        let mut profile = sample_maintainer();
        profile.id = "".to_string();
        let err = assess_maintainer(&profile, 1_800_000_000).expect_err("empty id must reject");
        assert_eq!(err, FragilityError::EmptyIdentifier);
    }

    #[test]
    fn whitespace_only_maintainer_id_rejected() {
        let mut profile = sample_maintainer();
        profile.id = "   ".to_string();
        let err = assess_maintainer(&profile, 1_800_000_000).expect_err("whitespace id rejects");
        assert_eq!(err, FragilityError::EmptyIdentifier);
    }

    #[test]
    fn empty_publisher_id_rejected() {
        let mut profile = sample_publisher();
        profile.id = "".to_string();
        let err = assess_publisher(&profile, 1_800_000_000).expect_err("empty id must reject");
        assert_eq!(err, FragilityError::EmptyIdentifier);
    }

    #[test]
    fn clock_skew_rejected_for_maintainer() {
        let mut profile = sample_maintainer();
        profile.active_since = 2_000_000_000;
        let err = assess_maintainer(&profile, 1_000_000_000).expect_err("clock skew rejects");
        match err {
            FragilityError::ClockSkew { now, active_since } => {
                assert_eq!(now, 1_000_000_000);
                assert_eq!(active_since, 2_000_000_000);
            }
            other => panic!("expected ClockSkew, got {:?}", other),
        }
    }

    #[test]
    fn score_is_in_unit_interval_for_pathological_input() {
        // Construct a profile that triggers every maintainer factor and
        // verify the accumulator clamps `total` to `[0.0, 1.0]`.
        let now = 1_800_000_000_i64;
        let profile = MaintainerProfile {
            id: "bob".to_string(),
            packages_owned: vec!["pkg".to_string()],
            total_downloads_per_month: 999_999_999,
            key_recovery_setup: false,
            active_since: 1_000_000_000,
            last_commit_ts: Some(now - 5_000 * 86_400),
            bus_factor: 0,
        };
        let score = assess_maintainer(&profile, now).expect("assess");
        assert!(
            (0.0..=1.0).contains(&score.total),
            "score.total out of range: {}",
            score.total
        );
        assert!(score.total.is_finite());
    }

    #[test]
    fn max_factor_is_none_for_non_fragile_maintainer() {
        let profile = sample_maintainer();
        let score = assess_maintainer(&profile, 1_800_000_000).expect("assess");
        assert!(
            score.factors.is_empty(),
            "sample maintainer is configured as non-fragile, got {:?}",
            score.factors
        );
        assert!(score.max_factor.is_none());
        assert_eq!(score.total, 0.0);
        assert!(!score.is_fragile());
    }

    #[test]
    fn max_factor_tracks_highest_severity() {
        // Build a profile that triggers both NoKeyRecovery (rank 3) and
        // StaleMaintainer (rank 2). The max factor must be NoKeyRecovery.
        let now = 1_800_000_000_i64;
        let profile = MaintainerProfile {
            id: "carol".to_string(),
            packages_owned: vec!["pkg".to_string()],
            total_downloads_per_month: 1,
            key_recovery_setup: false,
            active_since: 1_000_000_000,
            last_commit_ts: Some(now - 500 * 86_400),
            bus_factor: 5,
        };
        let score = assess_maintainer(&profile, now).expect("assess");
        match score.max_factor {
            Some(FragilityFactor::NoKeyRecovery) => {}
            other => panic!("expected NoKeyRecovery as max factor, got {:?}", other),
        }
    }

    #[test]
    fn fragility_score_content_hash_is_deterministic() {
        let score = FragilityScore {
            total: 0.5,
            factors: vec![FragilityFactor::SingleMaintainer],
            max_factor: Some(FragilityFactor::SingleMaintainer),
            computed_at: 1_700_000_000,
        };
        let h1 = score.content_hash().expect("hash");
        let h2 = score.content_hash().expect("hash");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64, "sha256 hex digest must be 64 chars");
    }

    #[test]
    fn fragility_score_content_hash_differs_across_payloads() {
        let a = FragilityScore {
            total: 0.5,
            factors: vec![FragilityFactor::SingleMaintainer],
            max_factor: Some(FragilityFactor::SingleMaintainer),
            computed_at: 1_700_000_000,
        };
        let b = FragilityScore {
            total: 0.5,
            factors: vec![FragilityFactor::NoKeyRecovery],
            max_factor: Some(FragilityFactor::NoKeyRecovery),
            computed_at: 1_700_000_000,
        };
        assert_ne!(a.content_hash().unwrap(), b.content_hash().unwrap());
    }

    #[test]
    fn fragility_factor_labels_are_stable() {
        // Stability check: if these labels change, downstream telemetry
        // dashboards and log alert rules will break.
        assert_eq!(
            FragilityFactor::SingleMaintainer.label(),
            "single_maintainer"
        );
        assert_eq!(FragilityFactor::NoKeyRecovery.label(), "no_key_recovery");
        assert_eq!(
            FragilityFactor::StaleMaintainer { staleness_days: 1 }.label(),
            "stale_maintainer"
        );
        assert_eq!(FragilityFactor::OrphanedPackage.label(), "orphaned_package");
        assert_eq!(
            FragilityFactor::UnrotatedKey { age_days: 1 }.label(),
            "unrotated_key"
        );
        assert_eq!(FragilityFactor::NoQuorum.label(), "no_quorum");
        assert_eq!(
            FragilityFactor::ConcentratedDownloads { share: 0.5 }.label(),
            "concentrated_downloads"
        );
    }

    #[test]
    fn fragility_factor_weights_are_finite_and_positive() {
        let variants = [
            FragilityFactor::SingleMaintainer,
            FragilityFactor::NoKeyRecovery,
            FragilityFactor::StaleMaintainer { staleness_days: 1 },
            FragilityFactor::OrphanedPackage,
            FragilityFactor::UnrotatedKey { age_days: 1 },
            FragilityFactor::NoQuorum,
            FragilityFactor::ConcentratedDownloads { share: 0.5 },
        ];
        for v in &variants {
            let w = v.weight();
            assert!(w.is_finite(), "weight non-finite: {:?}", v);
            assert!(w > 0.0, "weight non-positive: {:?}", v);
            assert!(w <= 1.0, "weight too large: {:?}", v);
        }
    }

    #[test]
    fn empty_score_constructor_is_non_fragile() {
        let score = FragilityScore::empty(1_700_000_000);
        assert_eq!(score.total, 0.0);
        assert!(score.factors.is_empty());
        assert!(score.max_factor.is_none());
        assert_eq!(score.computed_at, 1_700_000_000);
        assert!(!score.is_fragile());
    }
}
