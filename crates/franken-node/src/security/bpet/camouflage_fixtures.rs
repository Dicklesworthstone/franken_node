//! Training/regression fixtures for the camouflage detector (bd-35m7.1 sub-task 3/5).
//!
//! Each fixture pairs a [`TrajectorySeries`] with a [`DetectorConfig`] and a
//! list of [`ExpectedCamouflageHint`]s describing what the detector should
//! emit. The JSON shape under `tests/security/camouflage_fixtures/` is the
//! canonical source; this module exposes:
//!
//! * [`load_camouflage_fixture`] — parse fixture JSON into a [`CamouflageFixture`].
//! * [`evaluate_camouflage_fixture`] — run `detect_camouflage` and check the
//!   actual hint vector against the expected counts + sample-index spot checks.
//! * In-code synthesizers for all 10 fixtures so callers can build the
//!   fixture struct directly without touching the filesystem (the JSON file
//!   under `tests/` doubles as a canonical inspection surface).
//!
//! Hardening (per project conventions):
//! * Counter arithmetic uses `saturating_add`.
//! * All `f64` config values flow through [`DetectorConfig::validate`].
//! * Fixture loading never panics on malformed JSON: every error path returns
//!   [`DetectorError::InvalidConfig`] (no `unwrap`).
//! * Hint count maps cap their bucket counts at [`MAX_BUCKET_COUNT`].
//! * No unsafe.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::security::bpet::camouflage_detector::{
    DetectorConfig, DetectorError, MAX_CAMOUFLAGE_HINTS_PER_SERIES, detect_camouflage,
};
use crate::security::trajectory_gaming::{
    CamouflageKind, TrajectorySample, TrajectorySeries, append_sample,
};

/// Upper bound on the per-kind bucket count stored in
/// [`CamouflageVerdict::actual_hint_counts`]. Mirrors
/// [`MAX_CAMOUFLAGE_HINTS_PER_SERIES`] so a single bucket can never exceed
/// the total hint cap.
pub const MAX_BUCKET_COUNT: usize = MAX_CAMOUFLAGE_HINTS_PER_SERIES;

/// Stable label for the four camouflage kinds the detector emits.
///
/// Mirrors [`CamouflageKind`] but with a representation that survives JSON
/// round-trip via PascalCase (matches the convention used in fixture JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CamouflageKindLabel {
    PhaseShift,
    Dropout,
    DistributionMismatch,
    GradualCreep,
}

impl CamouflageKindLabel {
    pub fn from_kind(kind: CamouflageKind) -> Self {
        match kind {
            CamouflageKind::PhaseShift => CamouflageKindLabel::PhaseShift,
            CamouflageKind::Dropout => CamouflageKindLabel::Dropout,
            CamouflageKind::DistributionMismatch => CamouflageKindLabel::DistributionMismatch,
            CamouflageKind::GradualCreep => CamouflageKindLabel::GradualCreep,
        }
    }

    pub fn all() -> [CamouflageKindLabel; 4] {
        [
            CamouflageKindLabel::PhaseShift,
            CamouflageKindLabel::Dropout,
            CamouflageKindLabel::DistributionMismatch,
            CamouflageKindLabel::GradualCreep,
        ]
    }
}

/// Declared expectation for one camouflage kind in a fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedCamouflageHint {
    pub kind: CamouflageKindLabel,
    pub min_count: usize,
    pub max_count: usize,
    /// Optional spot-check: at least one emitted hint of `kind` must reference
    /// every index in this list within its `sample_indices`. Empty list means
    /// "do not check indices".
    pub expected_sample_indices_contains: Vec<usize>,
}

/// One fixture: input series + config + expected detector behaviour.
#[derive(Debug, Clone)]
pub struct CamouflageFixture {
    pub name: String,
    pub description: String,
    pub config: DetectorConfig,
    pub series: TrajectorySeries,
    pub expected_hints: Vec<ExpectedCamouflageHint>,
}

/// Outcome of running [`evaluate_camouflage_fixture`].
#[derive(Debug, Clone, PartialEq)]
pub struct CamouflageVerdict {
    pub passed: bool,
    pub actual_hint_counts: BTreeMap<CamouflageKindLabel, usize>,
    pub divergences: Vec<String>,
}

// ---------------------------------------------------------------------------
// JSON loader
// ---------------------------------------------------------------------------

/// Parse a [`CamouflageFixture`] from a JSON document.
///
/// The accepted shape mirrors the files under `tests/security/camouflage_fixtures/`:
///
/// ```json
/// {
///   "name": "phase_shift_clear",
///   "description": "...",
///   "config": { "phase_shift_threshold": 0.3, ... },
///   "series": { "samples": [...], "window_start": 0, "window_end": 100000 },
///   "expected_hints": [{"kind": "PhaseShift", "min_count": 1, ...}]
/// }
/// ```
pub fn load_camouflage_fixture(json: &str) -> Result<CamouflageFixture, DetectorError> {
    let v: Value = serde_json::from_str(json).map_err(|_| DetectorError::InvalidConfig)?;
    let obj = v.as_object().ok_or(DetectorError::InvalidConfig)?;

    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or(DetectorError::InvalidConfig)?
        .to_string();
    let description = obj
        .get("description")
        .and_then(Value::as_str)
        .ok_or(DetectorError::InvalidConfig)?
        .to_string();

    let config = parse_config(obj.get("config").ok_or(DetectorError::InvalidConfig)?)?;
    let series = parse_series(obj.get("series").ok_or(DetectorError::InvalidConfig)?)?;
    let expected_hints = parse_expected_hints(
        obj.get("expected_hints")
            .ok_or(DetectorError::InvalidConfig)?,
    )?;

    Ok(CamouflageFixture {
        name,
        description,
        config,
        series,
        expected_hints,
    })
}

fn parse_config(v: &Value) -> Result<DetectorConfig, DetectorError> {
    let obj = v.as_object().ok_or(DetectorError::InvalidConfig)?;
    let f = |k: &str| -> Result<f64, DetectorError> {
        obj.get(k)
            .and_then(Value::as_f64)
            .ok_or(DetectorError::InvalidConfig)
    };
    let u = |k: &str| -> Result<usize, DetectorError> {
        let n = obj
            .get(k)
            .and_then(Value::as_u64)
            .ok_or(DetectorError::InvalidConfig)?;
        usize::try_from(n).map_err(|_| DetectorError::InvalidConfig)
    };
    let cfg = DetectorConfig {
        phase_shift_threshold: f("phase_shift_threshold")?,
        dropout_threshold: f("dropout_threshold")?,
        distribution_kl_threshold: f("distribution_kl_threshold")?,
        creep_slope_threshold: f("creep_slope_threshold")?,
        min_samples_for_detection: u("min_samples_for_detection")?,
        window_size: u("window_size")?,
    };
    cfg.validate()?;
    Ok(cfg)
}

fn parse_series(v: &Value) -> Result<TrajectorySeries, DetectorError> {
    let obj = v.as_object().ok_or(DetectorError::InvalidConfig)?;
    let window_start = obj
        .get("window_start")
        .and_then(Value::as_i64)
        .ok_or(DetectorError::InvalidConfig)?;
    let window_end = obj
        .get("window_end")
        .and_then(Value::as_i64)
        .ok_or(DetectorError::InvalidConfig)?;
    let mut series = TrajectorySeries::new(window_start, window_end)
        .map_err(|_| DetectorError::InvalidConfig)?;
    let samples = obj
        .get("samples")
        .and_then(Value::as_array)
        .ok_or(DetectorError::InvalidConfig)?;
    for sample_v in samples {
        let s = parse_sample(sample_v)?;
        append_sample(&mut series, s).map_err(|_| DetectorError::InvalidConfig)?;
    }
    Ok(series)
}

fn parse_sample(v: &Value) -> Result<TrajectorySample, DetectorError> {
    let obj = v.as_object().ok_or(DetectorError::InvalidConfig)?;
    let ts = obj
        .get("ts")
        .and_then(Value::as_i64)
        .ok_or(DetectorError::InvalidConfig)?;
    let observed = parse_cap_map(
        obj.get("observed_capability")
            .ok_or(DetectorError::InvalidConfig)?,
    )?;
    let declared = parse_cap_map(
        obj.get("declared_capability")
            .ok_or(DetectorError::InvalidConfig)?,
    )?;
    TrajectorySample::new(ts, observed, declared).map_err(|_| DetectorError::InvalidConfig)
}

fn parse_cap_map(v: &Value) -> Result<BTreeMap<String, f64>, DetectorError> {
    let obj = v.as_object().ok_or(DetectorError::InvalidConfig)?;
    let mut out = BTreeMap::new();
    for (k, vv) in obj {
        let num = vv.as_f64().ok_or(DetectorError::InvalidConfig)?;
        if !num.is_finite() {
            return Err(DetectorError::InvalidConfig);
        }
        out.insert(k.clone(), num);
    }
    Ok(out)
}

fn parse_expected_hints(v: &Value) -> Result<Vec<ExpectedCamouflageHint>, DetectorError> {
    let arr = v.as_array().ok_or(DetectorError::InvalidConfig)?;
    let mut out: Vec<ExpectedCamouflageHint> = Vec::new();
    for h in arr {
        let h_obj = h.as_object().ok_or(DetectorError::InvalidConfig)?;
        let kind_str = h_obj
            .get("kind")
            .and_then(Value::as_str)
            .ok_or(DetectorError::InvalidConfig)?;
        let kind = match kind_str {
            "PhaseShift" => CamouflageKindLabel::PhaseShift,
            "Dropout" => CamouflageKindLabel::Dropout,
            "DistributionMismatch" => CamouflageKindLabel::DistributionMismatch,
            "GradualCreep" => CamouflageKindLabel::GradualCreep,
            _ => return Err(DetectorError::InvalidConfig),
        };
        let min_count = h_obj
            .get("min_count")
            .and_then(Value::as_u64)
            .ok_or(DetectorError::InvalidConfig)?;
        let max_count = h_obj
            .get("max_count")
            .and_then(Value::as_u64)
            .ok_or(DetectorError::InvalidConfig)?;
        let min_count = usize::try_from(min_count).map_err(|_| DetectorError::InvalidConfig)?;
        let max_count = usize::try_from(max_count).map_err(|_| DetectorError::InvalidConfig)?;
        if max_count < min_count {
            return Err(DetectorError::InvalidConfig);
        }
        let mut indices: Vec<usize> = Vec::new();
        if let Some(arr) = h_obj.get("expected_sample_indices_contains") {
            let arr = arr.as_array().ok_or(DetectorError::InvalidConfig)?;
            for n in arr {
                let n = n.as_u64().ok_or(DetectorError::InvalidConfig)?;
                indices.push(usize::try_from(n).map_err(|_| DetectorError::InvalidConfig)?);
            }
        }
        out.push(ExpectedCamouflageHint {
            kind,
            min_count,
            max_count,
            expected_sample_indices_contains: indices,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Run the detector on `fixture.series` with `fixture.config` and verify the
/// emitted hint vector matches `fixture.expected_hints`.
///
/// Returns a [`CamouflageVerdict`] whose `passed` flag is `true` iff:
/// * For every `ExpectedCamouflageHint`, the number of emitted hints of that
///   kind falls within `[min_count, max_count]`, and every required index in
///   `expected_sample_indices_contains` appears in at least one such hint.
/// * For every kind NOT in `expected_hints`, the emitted count is 0 (if the
///   fixture has any non-empty expected list this is enforced strictly; if
///   the expected list is empty, ALL kinds must be 0).
///
/// The detector itself is treated as untrusted from the validator's POV:
/// `divergences` accumulates every failed assertion so a single fixture
/// failure surfaces all root causes at once.
pub fn evaluate_camouflage_fixture(
    fixture: &CamouflageFixture,
) -> Result<CamouflageVerdict, DetectorError> {
    let hints = detect_camouflage(&fixture.series, &fixture.config)?;

    // Tally actual hint counts per kind (saturating).
    let mut counts: BTreeMap<CamouflageKindLabel, usize> = BTreeMap::new();
    for label in CamouflageKindLabel::all() {
        counts.insert(label, 0);
    }
    for h in &hints {
        let label = CamouflageKindLabel::from_kind(h.kind);
        let entry = counts.entry(label).or_insert(0);
        if *entry < MAX_BUCKET_COUNT {
            *entry = entry.saturating_add(1);
        }
    }

    let mut divergences: Vec<String> = Vec::new();

    // Per-expected-hint checks.
    for expected in &fixture.expected_hints {
        let actual = counts.get(&expected.kind).copied().unwrap_or(0);
        if actual < expected.min_count {
            divergences.push(format!(
                "kind {:?}: actual count {} < min_count {}",
                expected.kind, actual, expected.min_count
            ));
        }
        if actual > expected.max_count {
            divergences.push(format!(
                "kind {:?}: actual count {} > max_count {}",
                expected.kind, actual, expected.max_count
            ));
        }
        if !expected.expected_sample_indices_contains.is_empty() {
            let target_kind = label_to_kind(expected.kind);
            for &required in &expected.expected_sample_indices_contains {
                let found = hints
                    .iter()
                    .any(|h| h.kind == target_kind && h.sample_indices.contains(&required));
                if !found {
                    divergences.push(format!(
                        "kind {:?}: required sample_index {} not present in any emitted hint",
                        expected.kind, required
                    ));
                }
            }
        }
    }

    // Non-camouflage / unexpected-kind enforcement.
    let expected_kinds: std::collections::BTreeSet<CamouflageKindLabel> =
        fixture.expected_hints.iter().map(|e| e.kind).collect();
    if fixture.expected_hints.is_empty() {
        // Pure non-camouflage fixture: ALL kinds must be 0.
        for label in CamouflageKindLabel::all() {
            let actual = counts.get(&label).copied().unwrap_or(0);
            if actual != 0 {
                divergences.push(format!(
                    "non-camouflage fixture emitted {} hint(s) of kind {:?}",
                    actual, label
                ));
            }
        }
    } else {
        // Strict: any kind NOT explicitly listed must be 0.
        for label in CamouflageKindLabel::all() {
            if expected_kinds.contains(&label) {
                continue;
            }
            let actual = counts.get(&label).copied().unwrap_or(0);
            if actual != 0 {
                divergences.push(format!(
                    "unexpected kind {:?} emitted {} hint(s)",
                    label, actual
                ));
            }
        }
    }

    Ok(CamouflageVerdict {
        passed: divergences.is_empty(),
        actual_hint_counts: counts,
        divergences,
    })
}

fn label_to_kind(label: CamouflageKindLabel) -> CamouflageKind {
    match label {
        CamouflageKindLabel::PhaseShift => CamouflageKind::PhaseShift,
        CamouflageKindLabel::Dropout => CamouflageKind::Dropout,
        CamouflageKindLabel::DistributionMismatch => CamouflageKind::DistributionMismatch,
        CamouflageKindLabel::GradualCreep => CamouflageKind::GradualCreep,
    }
}

// ---------------------------------------------------------------------------
// In-code synthesizers (same data as the JSON fixtures, kept in lockstep)
// ---------------------------------------------------------------------------

fn cap(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();
    for (k, v) in pairs {
        m.insert((*k).to_string(), *v);
    }
    m
}

type FixtureSample = (i64, BTreeMap<String, f64>, BTreeMap<String, f64>);

fn build_series(samples: Vec<FixtureSample>) -> TrajectorySeries {
    let mut s = TrajectorySeries::new(0, 100_000).expect("valid window");
    for (ts, obs, decl) in samples {
        let sample = TrajectorySample::new(ts, obs, decl).expect("finite values");
        append_sample(&mut s, sample).expect("append ok");
    }
    s
}

pub fn fixture_phase_shift_clear() -> CamouflageFixture {
    let mut rows = Vec::new();
    for i in 0..20i64 {
        let v = if i < 10 { 0.1 } else { 0.9 };
        rows.push((i, cap(&[("net.egress", v)]), cap(&[("net.egress", 0.5)])));
    }
    CamouflageFixture {
        name: "phase_shift_clear".to_string(),
        description: "Observed metric jumps from 0.1 to 0.9 at step 10; declared steady at 0.5."
            .to_string(),
        config: DetectorConfig {
            phase_shift_threshold: 0.3,
            dropout_threshold: 0.99,
            distribution_kl_threshold: 100.0,
            creep_slope_threshold: 10.0,
            min_samples_for_detection: 8,
            window_size: 10,
        },
        series: build_series(rows),
        expected_hints: vec![ExpectedCamouflageHint {
            kind: CamouflageKindLabel::PhaseShift,
            min_count: 1,
            max_count: 5,
            expected_sample_indices_contains: vec![9, 10],
        }],
    }
}

pub fn fixture_dropout_clear() -> CamouflageFixture {
    let mut rows = Vec::new();
    for i in 0..16i64 {
        let obs_v = if i % 3 == 0 { 0.0 } else { 0.3 };
        rows.push((
            i,
            cap(&[("net.egress", obs_v)]),
            cap(&[("net.egress", 0.3)]),
        ));
    }
    CamouflageFixture {
        name: "dropout_clear".to_string(),
        description: "Observed value is 0 for ~33% of declared samples (declared always 0.3)."
            .to_string(),
        config: DetectorConfig {
            phase_shift_threshold: 100.0,
            dropout_threshold: 0.2,
            distribution_kl_threshold: 100.0,
            creep_slope_threshold: 100.0,
            min_samples_for_detection: 8,
            window_size: 10,
        },
        series: build_series(rows),
        expected_hints: vec![ExpectedCamouflageHint {
            kind: CamouflageKindLabel::Dropout,
            min_count: 1,
            max_count: 5,
            expected_sample_indices_contains: vec![],
        }],
    }
}

pub fn fixture_distribution_mismatch_clear() -> CamouflageFixture {
    let mut rows = Vec::new();
    for i in 0..16i64 {
        let obs_v = if i == 0 { 1.0 } else { 0.01 };
        rows.push((
            i,
            cap(&[("net.egress", obs_v)]),
            cap(&[("net.egress", 0.1)]),
        ));
    }
    CamouflageFixture {
        name: "distribution_mismatch_clear".to_string(),
        description: "Observed concentrates ~95% mass at first sample; declared is uniform."
            .to_string(),
        config: DetectorConfig {
            phase_shift_threshold: 100.0,
            dropout_threshold: 0.99,
            distribution_kl_threshold: 0.5,
            creep_slope_threshold: 100.0,
            min_samples_for_detection: 8,
            window_size: 10,
        },
        series: build_series(rows),
        expected_hints: vec![ExpectedCamouflageHint {
            kind: CamouflageKindLabel::DistributionMismatch,
            min_count: 1,
            max_count: 5,
            expected_sample_indices_contains: vec![0],
        }],
    }
}

pub fn fixture_gradual_creep_clear() -> CamouflageFixture {
    let mut rows = Vec::new();
    for i in 0..20i64 {
        let ratio = 0.5 + (i as f64 / 19.0) * 1.0;
        rows.push((
            i,
            cap(&[("net.egress", ratio * 0.3)]),
            cap(&[("net.egress", 0.3)]),
        ));
    }
    CamouflageFixture {
        name: "gradual_creep_clear".to_string(),
        description: "Observed/declared ratio creeps linearly from 0.5 to 1.5 over 20 samples."
            .to_string(),
        config: DetectorConfig {
            phase_shift_threshold: 1.0,
            dropout_threshold: 0.99,
            distribution_kl_threshold: 100.0,
            creep_slope_threshold: 0.01,
            min_samples_for_detection: 8,
            window_size: 10,
        },
        series: build_series(rows),
        expected_hints: vec![ExpectedCamouflageHint {
            kind: CamouflageKindLabel::GradualCreep,
            min_count: 1,
            max_count: 2,
            expected_sample_indices_contains: vec![],
        }],
    }
}

pub fn fixture_multi_kind() -> CamouflageFixture {
    let mut rows = Vec::new();
    let n = 20i64;
    for i in 0..n {
        let net_v = if i < n / 2 { 0.1 } else { 0.9 };
        let fs_v = if i % 2 == 0 { 0.0 } else { 0.2 };
        rows.push((
            i,
            cap(&[("net.egress", net_v), ("fs.write", fs_v)]),
            cap(&[("net.egress", 0.5), ("fs.write", 0.2)]),
        ));
    }
    CamouflageFixture {
        name: "multi_kind".to_string(),
        description: "Combined phase shift on net.egress and 50% dropout on fs.write.".to_string(),
        config: DetectorConfig {
            phase_shift_threshold: 0.3,
            dropout_threshold: 0.2,
            distribution_kl_threshold: 100.0,
            creep_slope_threshold: 10.0,
            min_samples_for_detection: 8,
            window_size: 10,
        },
        series: build_series(rows),
        expected_hints: vec![
            ExpectedCamouflageHint {
                kind: CamouflageKindLabel::PhaseShift,
                min_count: 1,
                max_count: 5,
                expected_sample_indices_contains: vec![9, 10],
            },
            ExpectedCamouflageHint {
                kind: CamouflageKindLabel::Dropout,
                min_count: 1,
                max_count: 5,
                expected_sample_indices_contains: vec![],
            },
        ],
    }
}

pub fn fixture_steady_state() -> CamouflageFixture {
    let mut rows = Vec::new();
    for i in 0..20i64 {
        rows.push((
            i,
            cap(&[("net.egress", 0.3), ("fs.write", 0.1)]),
            cap(&[("net.egress", 0.3), ("fs.write", 0.1)]),
        ));
    }
    CamouflageFixture {
        name: "steady_state".to_string(),
        description: "Observed equals declared; constant across the window.".to_string(),
        config: DetectorConfig {
            phase_shift_threshold: 0.3,
            dropout_threshold: 0.2,
            distribution_kl_threshold: 0.5,
            creep_slope_threshold: 0.01,
            min_samples_for_detection: 8,
            window_size: 10,
        },
        series: build_series(rows),
        expected_hints: vec![],
    }
}

pub fn fixture_coherent_drift() -> CamouflageFixture {
    let mut rows = Vec::new();
    for i in 0..20i64 {
        let v = 0.2 + (i as f64) * 0.03;
        rows.push((i, cap(&[("net.egress", v)]), cap(&[("net.egress", v)])));
    }
    CamouflageFixture {
        name: "coherent_drift".to_string(),
        description: "Both observed and declared drift together; ratio stays ~1.0.".to_string(),
        config: DetectorConfig {
            phase_shift_threshold: 0.6,
            dropout_threshold: 0.2,
            distribution_kl_threshold: 0.5,
            creep_slope_threshold: 0.05,
            min_samples_for_detection: 8,
            window_size: 10,
        },
        series: build_series(rows),
        expected_hints: vec![],
    }
}

pub fn fixture_noisy_but_aligned() -> CamouflageFixture {
    let mut rows = Vec::new();
    for i in 0..20i64 {
        let v = if i % 2 == 0 { 0.25 } else { 0.35 };
        rows.push((i, cap(&[("net.egress", v)]), cap(&[("net.egress", 0.30)])));
    }
    CamouflageFixture {
        name: "noisy_but_aligned".to_string(),
        description: "Observed zig-zags within ±0.05 of declared mean.".to_string(),
        config: DetectorConfig {
            phase_shift_threshold: 0.3,
            dropout_threshold: 0.5,
            distribution_kl_threshold: 0.5,
            creep_slope_threshold: 0.05,
            min_samples_for_detection: 8,
            window_size: 10,
        },
        series: build_series(rows),
        expected_hints: vec![],
    }
}

pub fn fixture_partial_observation() -> CamouflageFixture {
    let mut rows = Vec::new();
    for i in 0..20i64 {
        if i % 3 == 0 {
            rows.push((i, cap(&[("net.egress", 0.0)]), cap(&[("net.egress", 0.0)])));
        } else {
            rows.push((i, cap(&[("net.egress", 0.3)]), cap(&[("net.egress", 0.3)])));
        }
    }
    CamouflageFixture {
        name: "partial_observation".to_string(),
        description: "Capability dormant on some samples but declared 0 there too; not a dropout."
            .to_string(),
        config: DetectorConfig {
            phase_shift_threshold: 0.4,
            dropout_threshold: 0.2,
            distribution_kl_threshold: 0.5,
            creep_slope_threshold: 0.05,
            min_samples_for_detection: 8,
            window_size: 10,
        },
        series: build_series(rows),
        expected_hints: vec![],
    }
}

pub fn fixture_small_excursion() -> CamouflageFixture {
    let mut rows = Vec::new();
    for i in 0..20i64 {
        if i == 7 {
            rows.push((
                i,
                cap(&[("net.egress", 0.0), ("fs.write", 0.0)]),
                cap(&[("net.egress", 0.3), ("fs.write", 0.1)]),
            ));
        } else {
            rows.push((
                i,
                cap(&[("net.egress", 0.3), ("fs.write", 0.1)]),
                cap(&[("net.egress", 0.3), ("fs.write", 0.1)]),
            ));
        }
    }
    CamouflageFixture {
        name: "small_excursion".to_string(),
        description:
            "Single 1-sample dropout in a 20-sample series; below window dropout threshold."
                .to_string(),
        config: DetectorConfig {
            phase_shift_threshold: 0.3,
            dropout_threshold: 0.5,
            distribution_kl_threshold: 0.5,
            creep_slope_threshold: 0.05,
            min_samples_for_detection: 8,
            window_size: 10,
        },
        series: build_series(rows),
        expected_hints: vec![],
    }
}

/// All ten fixtures in canonical order: 5 camouflage cases first, then 5 benign.
pub fn all_fixtures() -> Vec<CamouflageFixture> {
    vec![
        fixture_phase_shift_clear(),
        fixture_dropout_clear(),
        fixture_distribution_mismatch_clear(),
        fixture_gradual_creep_clear(),
        fixture_multi_kind(),
        fixture_steady_state(),
        fixture_coherent_drift(),
        fixture_noisy_but_aligned(),
        fixture_partial_observation(),
        fixture_small_excursion(),
    ]
}

// ---------------------------------------------------------------------------
// Inline tests: every synthesizer's verdict must `passed=true`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn run(fixture: CamouflageFixture) {
        let verdict = evaluate_camouflage_fixture(&fixture).expect("detector did not error");
        assert!(
            verdict.passed,
            "fixture `{}` failed:\n  divergences: {:#?}\n  counts: {:?}",
            fixture.name, verdict.divergences, verdict.actual_hint_counts
        );
    }

    #[test]
    fn synthesizer_phase_shift_clear_passes() {
        run(fixture_phase_shift_clear());
    }

    #[test]
    fn synthesizer_dropout_clear_passes() {
        run(fixture_dropout_clear());
    }

    #[test]
    fn synthesizer_distribution_mismatch_clear_passes() {
        run(fixture_distribution_mismatch_clear());
    }

    #[test]
    fn synthesizer_gradual_creep_clear_passes() {
        run(fixture_gradual_creep_clear());
    }

    #[test]
    fn synthesizer_multi_kind_passes() {
        run(fixture_multi_kind());
    }

    #[test]
    fn synthesizer_steady_state_passes() {
        run(fixture_steady_state());
    }

    #[test]
    fn synthesizer_coherent_drift_passes() {
        run(fixture_coherent_drift());
    }

    #[test]
    fn synthesizer_noisy_but_aligned_passes() {
        run(fixture_noisy_but_aligned());
    }

    #[test]
    fn synthesizer_partial_observation_passes() {
        run(fixture_partial_observation());
    }

    #[test]
    fn synthesizer_small_excursion_passes() {
        run(fixture_small_excursion());
    }

    #[test]
    fn all_fixtures_returns_ten_entries() {
        assert_eq!(all_fixtures().len(), 10);
    }

    #[test]
    fn load_round_trip_matches_synthesizer_on_phase_shift_clear() {
        // Serialize the synthesizer fixture to the canonical JSON shape and
        // round-trip it through `load_camouflage_fixture`.
        let f = fixture_phase_shift_clear();
        let samples_json: Vec<Value> = f
            .series
            .samples
            .iter()
            .map(|s| {
                serde_json::json!({
                    "ts": s.ts,
                    "observed_capability": s.observed_capability,
                    "declared_capability": s.declared_capability,
                })
            })
            .collect();
        let payload = serde_json::json!({
            "name": f.name,
            "description": f.description,
            "config": {
                "phase_shift_threshold": f.config.phase_shift_threshold,
                "dropout_threshold": f.config.dropout_threshold,
                "distribution_kl_threshold": f.config.distribution_kl_threshold,
                "creep_slope_threshold": f.config.creep_slope_threshold,
                "min_samples_for_detection": f.config.min_samples_for_detection,
                "window_size": f.config.window_size,
            },
            "series": {
                "samples": samples_json,
                "window_start": f.series.window_start,
                "window_end": f.series.window_end,
            },
            "expected_hints": [
                {
                    "kind": "PhaseShift",
                    "min_count": 1,
                    "max_count": 5,
                    "expected_sample_indices_contains": [9, 10],
                }
            ],
        });
        let json = serde_json::to_string(&payload).unwrap();
        let parsed = load_camouflage_fixture(&json).expect("load ok");
        assert_eq!(parsed.name, f.name);
        assert_eq!(parsed.series.samples.len(), f.series.samples.len());
        let verdict = evaluate_camouflage_fixture(&parsed).expect("eval ok");
        assert!(
            verdict.passed,
            "round-tripped fixture failed: {:?}",
            verdict
        );
    }

    #[test]
    fn load_rejects_unknown_kind_label() {
        let json = r#"{
          "name": "x", "description": "y",
          "config": {"phase_shift_threshold": 0.3, "dropout_threshold": 0.2, "distribution_kl_threshold": 0.5, "creep_slope_threshold": 0.01, "min_samples_for_detection": 8, "window_size": 10},
          "series": {"samples": [], "window_start": 0, "window_end": 1000},
          "expected_hints": [{"kind": "NotAKind", "min_count": 0, "max_count": 0, "expected_sample_indices_contains": []}]
        }"#;
        let err = load_camouflage_fixture(json).unwrap_err();
        assert_eq!(err, DetectorError::InvalidConfig);
    }

    #[test]
    fn evaluate_reports_divergence_when_actual_below_min() {
        // Take a benign fixture but assert we expect a phase shift -> should diverge.
        let mut f = fixture_steady_state();
        f.expected_hints = vec![ExpectedCamouflageHint {
            kind: CamouflageKindLabel::PhaseShift,
            min_count: 1,
            max_count: 5,
            expected_sample_indices_contains: vec![],
        }];
        let verdict = evaluate_camouflage_fixture(&f).expect("eval ok");
        assert!(!verdict.passed);
        assert!(
            verdict
                .divergences
                .iter()
                .any(|d| d.contains("< min_count"))
        );
    }
}
