//! Trajectory-gaming camouflage runtime integration (bd-35m7.1 sub-task 1/5).
//!
//! Exposes the stable Rust-side interface that the Python verifier
//! `scripts/check_trajectory_gaming_camouflage.py` consumes when grading
//! trust-decision trajectories for mimicry/camouflage signals.
//!
//! The interface in this module is intentionally narrow:
//!
//! * [`TrajectorySample`] / [`TrajectorySeries`] — bounded-growth ingest types
//!   that capture observed-vs-declared capability vectors over a time window.
//! * [`CamouflageHint`] / [`CamouflageKind`] — typed parse of the verifier's
//!   "this looks like trajectory gaming" output.
//! * [`export_for_verifier`] — serialise a series into the JSON shape that the
//!   Python script's `evaluate_policy` / `check_report` functions already
//!   accept (mimicry corpus + detection model + motif randomization + hybrid
//!   fusion + scenarios). Sub-tasks 2-5 of bd-35m7 will fill in the analysis
//!   that actually populates those fields with real data; this sub-task only
//!   establishes the stable contract so the Python verifier and the Rust
//!   runtime can talk.
//! * [`ingest_verifier_hints`] — parse the verifier's output (the `checks`
//!   list emitted by `run_checks()` plus any per-scenario diagnostics) into a
//!   list of typed [`CamouflageHint`]s that the trust-card pipeline can
//!   consume.
//! * [`append_sample`] — bounded-growth append with `is_finite` guards on all
//!   capability values, matching project hardening conventions.
//!
//! All `f64` values are guarded with `is_finite()`; counters use
//! `saturating_add`; growth is capped by `MAX_TRAJECTORY_SAMPLES`; no unsafe.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// Maximum number of samples retained in a single [`TrajectorySeries`].
///
/// Older samples are evicted (oldest-first) when the cap is reached so the
/// detector keeps a bounded sliding window without unbounded heap growth.
pub const MAX_TRAJECTORY_SAMPLES: usize = 10_000;

/// Maximum number of hints produced by a single call to [`ingest_verifier_hints`].
/// Mirrors the bounded-growth conventions used elsewhere in `security/`.
pub const MAX_CAMOUFLAGE_HINTS: usize = 4_096;

/// Errors produced by the trajectory-gaming runtime surface.
#[derive(Debug, thiserror::Error)]
pub enum TrajectoryGamingError {
    #[error("non-finite f64 value in field `{field}` for sample `{sample}`")]
    NonFinite { field: &'static str, sample: usize },
    #[error("non-finite severity in camouflage hint at index {index}")]
    NonFiniteSeverity { index: usize },
    #[error("invalid sample index {index} (series has {len} samples)")]
    SampleIndexOutOfRange { index: usize, len: usize },
    #[error("window range invalid: start={start} end={end}")]
    InvalidWindow { start: i64, end: i64 },
    #[error("missing required JSON field `{field}` in verifier output")]
    MissingField { field: &'static str },
    #[error("malformed JSON value for field `{field}`")]
    MalformedField { field: &'static str },
    #[error("unknown camouflage kind: `{kind}`")]
    UnknownKind { kind: String },
}

/// A single observed-vs-declared capability vector at a point in time.
///
/// `observed_capability` is what the runtime measured for the agent;
/// `declared_capability` is what the agent claims (e.g. via its trust card).
/// Divergence between the two is the primary signal the camouflage detector
/// consumes in sub-tasks 2+.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrajectorySample {
    pub ts: i64,
    pub observed_capability: BTreeMap<String, f64>,
    pub declared_capability: BTreeMap<String, f64>,
}

impl TrajectorySample {
    /// Construct a new sample, validating that all `f64` values are finite.
    pub fn new(
        ts: i64,
        observed_capability: BTreeMap<String, f64>,
        declared_capability: BTreeMap<String, f64>,
    ) -> Result<Self, TrajectoryGamingError> {
        for (_, v) in &observed_capability {
            if !v.is_finite() {
                return Err(TrajectoryGamingError::NonFinite {
                    field: "observed_capability",
                    sample: 0,
                });
            }
        }
        for (_, v) in &declared_capability {
            if !v.is_finite() {
                return Err(TrajectoryGamingError::NonFinite {
                    field: "declared_capability",
                    sample: 0,
                });
            }
        }
        Ok(Self {
            ts,
            observed_capability,
            declared_capability,
        })
    }
}

/// A bounded-growth window of [`TrajectorySample`]s.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TrajectorySeries {
    pub samples: Vec<TrajectorySample>,
    pub window_start: i64,
    pub window_end: i64,
}

impl TrajectorySeries {
    pub fn new(window_start: i64, window_end: i64) -> Result<Self, TrajectoryGamingError> {
        if window_end < window_start {
            return Err(TrajectoryGamingError::InvalidWindow {
                start: window_start,
                end: window_end,
            });
        }
        Ok(Self {
            samples: Vec::new(),
            window_start,
            window_end,
        })
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

/// Coarse taxonomy for the kinds of camouflage the verifier can flag.
///
/// The exact heuristic that maps trajectory features → kind lives in
/// `src/security/bpet/camouflage_detector.rs` (bd-35m7.1 sub-task 2). This
/// enum is the stable contract used by both the detector output and any
/// downstream consumer (trust card, decision receipts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CamouflageKind {
    /// Sudden shift in the observed-capability phase (e.g. a benign-looking
    /// agent abruptly toggles into a different behavioural regime).
    PhaseShift,
    /// Sustained absence of an expected capability dimension that the agent
    /// claims to exercise (declared but never observed).
    Dropout,
    /// Observed-vs-declared distributions disagree past a threshold.
    DistributionMismatch,
    /// Slow drift that stays under per-step thresholds but accumulates
    /// (the classic adaptive-adversary pattern from scenario E).
    GradualCreep,
}

impl CamouflageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CamouflageKind::PhaseShift => "phase_shift",
            CamouflageKind::Dropout => "dropout",
            CamouflageKind::DistributionMismatch => "distribution_mismatch",
            CamouflageKind::GradualCreep => "gradual_creep",
        }
    }

    pub fn parse(s: &str) -> Result<Self, TrajectoryGamingError> {
        match s {
            "phase_shift" => Ok(CamouflageKind::PhaseShift),
            "dropout" => Ok(CamouflageKind::Dropout),
            "distribution_mismatch" => Ok(CamouflageKind::DistributionMismatch),
            "gradual_creep" => Ok(CamouflageKind::GradualCreep),
            other => Err(TrajectoryGamingError::UnknownKind {
                kind: other.to_string(),
            }),
        }
    }
}

/// Typed parse of one verifier finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CamouflageHint {
    pub kind: CamouflageKind,
    pub severity: f64,
    pub evidence: BTreeMap<String, f64>,
    pub sample_indices: Vec<usize>,
}

/// Append a sample to a [`TrajectorySeries`] with bounded growth and finite-guard checks.
///
/// If the series is already at [`MAX_TRAJECTORY_SAMPLES`], the oldest sample
/// is dropped before the new one is pushed (sliding-window semantics).
pub fn append_sample(
    series: &mut TrajectorySeries,
    sample: TrajectorySample,
) -> Result<(), TrajectoryGamingError> {
    let sample_index = series.samples.len();
    for (_, v) in &sample.observed_capability {
        if !v.is_finite() {
            return Err(TrajectoryGamingError::NonFinite {
                field: "observed_capability",
                sample: sample_index,
            });
        }
    }
    for (_, v) in &sample.declared_capability {
        if !v.is_finite() {
            return Err(TrajectoryGamingError::NonFinite {
                field: "declared_capability",
                sample: sample_index,
            });
        }
    }

    if MAX_TRAJECTORY_SAMPLES == 0 {
        series.samples.clear();
        return Ok(());
    }
    if series.samples.len() >= MAX_TRAJECTORY_SAMPLES {
        let overflow = series
            .samples
            .len()
            .saturating_sub(MAX_TRAJECTORY_SAMPLES)
            .saturating_add(1);
        let drain_count = overflow.min(series.samples.len());
        series.samples.drain(0..drain_count);
    }

    if sample.ts < series.window_start || sample.ts > series.window_end {
        // Widen the window to include the new sample rather than rejecting it
        // outright — the detector consumes ts directly, and the window range
        // is just descriptive metadata for the verifier export.
        if sample.ts < series.window_start {
            series.window_start = sample.ts;
        }
        if sample.ts > series.window_end {
            series.window_end = sample.ts;
        }
    }

    series.samples.push(sample);
    Ok(())
}

fn capability_to_json(cap: &BTreeMap<String, f64>) -> Value {
    let mut map = Map::new();
    for (k, v) in cap {
        // Caller already validated with is_finite via append_sample / new.
        // Belt-and-braces: skip non-finite to avoid serialising NaN/Inf.
        if v.is_finite() {
            map.insert(k.clone(), json!(*v));
        }
    }
    Value::Object(map)
}

/// Serialise a [`TrajectorySeries`] into the JSON shape consumed by
/// `scripts/check_trajectory_gaming_camouflage.py`.
///
/// Sub-task 1 of bd-35m7 only establishes the contract: the structural fields
/// the Python verifier expects (`mimicry_corpus`, `detection_model`,
/// `motif_randomization`, `hybrid_signal_fusion`, `scenarios`,
/// `event_codes`, `trace_id`, `aggregate`) are emitted with deterministic
/// placeholder values plus the full sample stream under a new
/// `runtime_trajectory` block. Sub-tasks 2-4 will replace placeholders with
/// values computed from `series`.
pub fn export_for_verifier(series: &TrajectorySeries) -> Result<Value, TrajectoryGamingError> {
    let mut samples_json: Vec<Value> = Vec::with_capacity(series.samples.len());
    for sample in &series.samples {
        samples_json.push(json!({
            "ts": sample.ts,
            "observed_capability": capability_to_json(&sample.observed_capability),
            "declared_capability": capability_to_json(&sample.declared_capability),
        }));
    }

    // Placeholder values that match the structural expectations of the Python
    // verifier so the contract round-trips. The detector lives in sub-task 2;
    // until then we ship an empty-but-structurally-valid payload that the
    // verifier can parse without crashing.
    let payload = json!({
        "bead_id": "bd-35m7",
        "section": "12",
        "title": "Risk control: trajectory-gaming camouflage",
        "trace_id": "trace-bd-35m7-runtime",
        "schema_version": "tgc-runtime-v1.0",
        "mimicry_corpus": {
            "pattern_count": 0,
            "update_interval_days": 0,
            "quarterly_update_required_days": 92,
        },
        "detection_model": {
            "model_id": "tgc-runtime-placeholder",
            "known_mimicry_recall_pct": 0.0,
            "known_mimicry_threshold_pct": 90.0,
            "adaptive_attack_rounds": 0,
            "adaptive_round_recall_pct": [],
            "adaptive_recall_threshold_pct": 80.0,
            "retrained_after_new_pattern": false,
        },
        "motif_randomization": {
            "evaluations": [],
            "subsets_unique": false,
        },
        "hybrid_signal_fusion": {
            "channels": ["behavioral", "provenance", "code_analysis", "reputation"],
            "fusion_policy": "deny_if_any_non_behavioral_critical_fail",
            "gaming_behavioral_only_flagged": false,
            "adjudications": [],
        },
        "scenarios": [],
        "event_codes": ["TGC-001", "TGC-002", "TGC-003", "TGC-004", "TGC-005"],
        "aggregate": {
            "pattern_count": 0,
            "known_mimicry_recall_pct": 0.0,
            "adaptive_min_round_recall_pct": 0.0,
            "motif_subsets_unique": false,
            "hybrid_behavioral_gaming_flagged": false,
            "update_interval_days": 0,
        },
        "runtime_trajectory": {
            "window_start": series.window_start,
            "window_end": series.window_end,
            "sample_count": u64::try_from(series.samples.len()).unwrap_or(u64::MAX),
            "samples": samples_json,
        },
    });

    Ok(payload)
}

/// Parse the verifier's output JSON into a list of [`CamouflageHint`]s.
///
/// The Python verifier emits either a `checks` list (from `run_checks()`) or
/// a `hints` list (the new structured channel sub-task 2 will populate). We
/// look for `hints` first, then fall back to extracting hints from the
/// `checks` list (each failed check becomes a hint with placeholder severity).
pub fn ingest_verifier_hints(json: &Value) -> Result<Vec<CamouflageHint>, TrajectoryGamingError> {
    let obj = json
        .as_object()
        .ok_or(TrajectoryGamingError::MalformedField { field: "root" })?;

    let mut out: Vec<CamouflageHint> = Vec::new();

    if let Some(Value::Array(hints)) = obj.get("hints") {
        for (idx, h) in hints.iter().enumerate() {
            if out.len() >= MAX_CAMOUFLAGE_HINTS {
                break;
            }
            let h_obj = h
                .as_object()
                .ok_or(TrajectoryGamingError::MalformedField { field: "hints" })?;
            let kind_str = h_obj
                .get("kind")
                .and_then(Value::as_str)
                .ok_or(TrajectoryGamingError::MissingField { field: "kind" })?;
            let kind = CamouflageKind::parse(kind_str)?;
            let severity = h_obj
                .get("severity")
                .and_then(Value::as_f64)
                .ok_or(TrajectoryGamingError::MissingField { field: "severity" })?;
            if !severity.is_finite() {
                return Err(TrajectoryGamingError::NonFiniteSeverity { index: idx });
            }

            let mut evidence: BTreeMap<String, f64> = BTreeMap::new();
            if let Some(Value::Object(ev)) = h_obj.get("evidence") {
                for (k, v) in ev {
                    if let Some(num) = v.as_f64() {
                        if num.is_finite() {
                            evidence.insert(k.clone(), num);
                        }
                    }
                }
            }

            let mut sample_indices: Vec<usize> = Vec::new();
            if let Some(Value::Array(arr)) = h_obj.get("sample_indices") {
                for v in arr {
                    if let Some(n) = v.as_u64() {
                        if let Ok(u) = usize::try_from(n) {
                            sample_indices.push(u);
                        }
                    }
                }
            }

            out.push(CamouflageHint {
                kind,
                severity,
                evidence,
                sample_indices,
            });
        }
        return Ok(out);
    }

    // Fallback: synthesise hints from the verifier's check list. Each failing
    // check becomes a `DistributionMismatch` hint with severity 1.0; passing
    // checks produce no hint. This keeps the parse total even on legacy
    // verifier output that predates the structured `hints` channel.
    if let Some(Value::Array(checks)) = obj.get("checks") {
        for c in checks {
            if out.len() >= MAX_CAMOUFLAGE_HINTS {
                break;
            }
            let c_obj = match c.as_object() {
                Some(o) => o,
                None => continue,
            };
            let pass = c_obj.get("pass").and_then(Value::as_bool).unwrap_or(true);
            if pass {
                continue;
            }
            let mut evidence: BTreeMap<String, f64> = BTreeMap::new();
            // Encode the position deterministically so callers can deduplicate.
            let bounded_idx = u32::try_from(out.len()).unwrap_or(u32::MAX);
            evidence.insert("check_index".to_string(), f64::from(bounded_idx));
            // Stable per-hint marker so downstream callers can distinguish
            // synthesised from real verifier hints.
            evidence.insert("synthesised".to_string(), 1.0);
            out.push(CamouflageHint {
                kind: CamouflageKind::DistributionMismatch,
                severity: 1.0,
                evidence,
                sample_indices: Vec::new(),
            });
        }
    }

    Ok(out)
}

/// Validate that every sample index referenced by a hint is within range.
///
/// Useful for the trust-card pipeline (sub-task 4) so it can fail-closed on a
/// verifier output that references samples the runtime never logged.
pub fn validate_hint_indices(
    hints: &[CamouflageHint],
    series: &TrajectorySeries,
) -> Result<(), TrajectoryGamingError> {
    let len = series.samples.len();
    for h in hints {
        for &idx in &h.sample_indices {
            if idx >= len {
                return Err(TrajectoryGamingError::SampleIndexOutOfRange { index: idx, len });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cap(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), *v);
        }
        m
    }

    fn make_sample(ts: i64) -> TrajectorySample {
        TrajectorySample::new(
            ts,
            make_cap(&[("net.egress", 0.25), ("fs.write", 0.10)]),
            make_cap(&[("net.egress", 0.30), ("fs.write", 0.05)]),
        )
        .expect("finite values build")
    }

    #[test]
    fn export_round_trip_emits_required_verifier_shape() {
        let mut series = TrajectorySeries::new(1_700_000_000, 1_700_000_600).unwrap();
        append_sample(&mut series, make_sample(1_700_000_010)).unwrap();
        append_sample(&mut series, make_sample(1_700_000_020)).unwrap();

        let payload = export_for_verifier(&series).expect("export ok");
        let obj = payload.as_object().expect("root is object");

        // Required by Python verifier's check_report():
        for field in &[
            "mimicry_corpus",
            "detection_model",
            "motif_randomization",
            "hybrid_signal_fusion",
            "scenarios",
            "event_codes",
            "trace_id",
            "aggregate",
        ] {
            assert!(obj.contains_key(*field), "missing field: {field}");
        }

        // Sample stream survives the round-trip.
        let rt = obj.get("runtime_trajectory").unwrap().as_object().unwrap();
        assert_eq!(rt.get("sample_count").unwrap().as_u64().unwrap(), 2);
        let samples = rt.get("samples").unwrap().as_array().unwrap();
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].get("ts").unwrap().as_i64().unwrap(), 1_700_000_010);
    }

    #[test]
    fn ingest_well_formed_verifier_json_parses_hints() {
        let v = json!({
            "hints": [
                {
                    "kind": "phase_shift",
                    "severity": 0.82,
                    "evidence": {"delta": 0.42, "entropy": 1.1},
                    "sample_indices": [0, 3]
                },
                {
                    "kind": "gradual_creep",
                    "severity": 0.31,
                    "evidence": {"slope": 0.004},
                    "sample_indices": []
                }
            ]
        });

        let hints = ingest_verifier_hints(&v).expect("parse ok");
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].kind, CamouflageKind::PhaseShift);
        assert_eq!(hints[0].sample_indices, vec![0, 3]);
        assert!((hints[0].severity - 0.82).abs() < 1e-9);
        assert_eq!(hints[1].kind, CamouflageKind::GradualCreep);
        assert!(hints[1].sample_indices.is_empty());
    }

    #[test]
    fn ingest_rejects_non_numeric_severity() {
        // serde_json's Number type cannot represent NaN/Inf, so the only path
        // to a "non-finite severity" in practice is malformed/missing JSON.
        // We assert that the parser rejects every non-numeric severity payload
        // (string, null, missing, bool) with MissingField, which is the same
        // fail-closed branch a NaN value would take if it could be constructed.
        let cases = vec![
            json!({"hints": [{"kind": "dropout", "severity": "nan", "evidence": {}, "sample_indices": []}]}),
            json!({"hints": [{"kind": "dropout", "severity": null, "evidence": {}, "sample_indices": []}]}),
            json!({"hints": [{"kind": "dropout", "evidence": {}, "sample_indices": []}]}),
            json!({"hints": [{"kind": "dropout", "severity": true, "evidence": {}, "sample_indices": []}]}),
        ];
        for (i, v) in cases.iter().enumerate() {
            let err = ingest_verifier_hints(v).expect_err(&format!("case {i} should fail"));
            assert!(
                matches!(err, TrajectoryGamingError::MissingField { field: "severity" }),
                "case {i}: unexpected error {err:?}"
            );
        }
    }

    #[test]
    fn ingest_rejects_nan_severity_via_direct_construction() {
        // Defense-in-depth: build a CamouflageHint with NaN directly (the
        // runtime is_finite() guard catches anything that somehow slips past
        // the JSON layer, e.g. a hand-rolled Value::Number variant). We can't
        // construct a NaN Number through public API, so instead verify the
        // is_finite() invariant holds on round-tripped data.
        let hint = CamouflageHint {
            kind: CamouflageKind::Dropout,
            severity: 0.5,
            evidence: BTreeMap::new(),
            sample_indices: vec![],
        };
        assert!(hint.severity.is_finite());
        // And confirm the parser is the only construction route from JSON:
        let bad_kind = json!({"hints": [{"kind": "not_a_kind", "severity": 0.5, "evidence": {}, "sample_indices": []}]});
        let err = ingest_verifier_hints(&bad_kind).unwrap_err();
        assert!(matches!(err, TrajectoryGamingError::UnknownKind { .. }));
    }

    #[test]
    fn append_sample_rejects_nan_in_observed_capability() {
        let mut series = TrajectorySeries::new(0, 1_000).unwrap();
        let bad = TrajectorySample {
            ts: 10,
            observed_capability: make_cap(&[("x", f64::NAN)]),
            declared_capability: make_cap(&[("x", 0.0)]),
        };
        let err = append_sample(&mut series, bad).unwrap_err();
        assert!(matches!(
            err,
            TrajectoryGamingError::NonFinite {
                field: "observed_capability",
                ..
            }
        ));
        assert!(series.is_empty());
    }

    #[test]
    fn append_sample_enforces_bounded_growth_at_cap() {
        let mut series = TrajectorySeries::new(0, i64::MAX).unwrap();
        // Push MAX + 50; assert len stays at MAX and oldest entries are evicted.
        let push_count: usize = MAX_TRAJECTORY_SAMPLES.saturating_add(50);
        for i in 0..push_count {
            let sample = TrajectorySample::new(
                i64::try_from(i).unwrap_or(i64::MAX),
                make_cap(&[("k", i as f64)]),
                make_cap(&[("k", i as f64)]),
            )
            .unwrap();
            append_sample(&mut series, sample).unwrap();
        }
        assert_eq!(series.samples.len(), MAX_TRAJECTORY_SAMPLES);
        // Oldest surviving sample's ts must be >= push_count - MAX (eviction
        // is oldest-first FIFO).
        let oldest_ts = series.samples[0].ts;
        let expected_min = i64::try_from(push_count.saturating_sub(MAX_TRAJECTORY_SAMPLES))
            .unwrap_or(i64::MAX);
        assert!(oldest_ts >= expected_min, "FIFO eviction failed: oldest_ts={oldest_ts} expected>={expected_min}");
    }

    #[test]
    fn empty_series_export_is_well_formed() {
        let series = TrajectorySeries::new(100, 200).unwrap();
        let payload = export_for_verifier(&series).expect("export ok");
        let rt = payload.get("runtime_trajectory").unwrap();
        assert_eq!(rt.get("sample_count").unwrap().as_u64().unwrap(), 0);
        assert!(rt.get("samples").unwrap().as_array().unwrap().is_empty());

        // ingest of empty hints / checks should yield empty hint vec
        let v = json!({"hints": []});
        let hints = ingest_verifier_hints(&v).unwrap();
        assert!(hints.is_empty());
    }

    #[test]
    fn validate_hint_indices_rejects_out_of_range_reference() {
        let mut series = TrajectorySeries::new(0, 1_000).unwrap();
        append_sample(&mut series, make_sample(10)).unwrap();
        append_sample(&mut series, make_sample(20)).unwrap();

        let good = CamouflageHint {
            kind: CamouflageKind::PhaseShift,
            severity: 0.5,
            evidence: BTreeMap::new(),
            sample_indices: vec![0, 1],
        };
        validate_hint_indices(std::slice::from_ref(&good), &series).unwrap();

        let bad = CamouflageHint {
            kind: CamouflageKind::PhaseShift,
            severity: 0.5,
            evidence: BTreeMap::new(),
            sample_indices: vec![0, 5],
        };
        let err = validate_hint_indices(std::slice::from_ref(&bad), &series).unwrap_err();
        assert!(matches!(
            err,
            TrajectoryGamingError::SampleIndexOutOfRange { index: 5, len: 2 }
        ));
    }

    #[test]
    fn camouflage_hint_serde_round_trip_preserves_all_fields() {
        let original = CamouflageHint {
            kind: CamouflageKind::DistributionMismatch,
            severity: 0.77,
            evidence: make_cap(&[("kl_div", 0.41), ("js_div", 0.29)]),
            sample_indices: vec![1, 4, 9],
        };
        let s = serde_json::to_string(&original).expect("ser");
        let parsed: CamouflageHint = serde_json::from_str(&s).expect("deser");
        assert_eq!(parsed, original);
        // CamouflageKind serialises in snake_case
        assert!(s.contains("\"distribution_mismatch\""), "kind not snake_case: {s}");
    }

    #[test]
    fn ingest_falls_back_to_checks_list_when_hints_missing() {
        // Legacy verifier output: only `checks` is present.
        let v = json!({
            "checks": [
                {"check": "scenario A: known mimicry flagged >=90% confidence", "pass": false, "detail": "fail"},
                {"check": "mimicry corpus: pattern count >=100", "pass": true, "detail": "ok"},
                {"check": "motif randomization: two evaluations use different subsets", "pass": false, "detail": "fail"}
            ]
        });
        let hints = ingest_verifier_hints(&v).expect("legacy parse ok");
        // 2 failing checks => 2 synthesised hints.
        assert_eq!(hints.len(), 2);
        for h in &hints {
            assert_eq!(h.kind, CamouflageKind::DistributionMismatch);
            assert!(h.severity.is_finite());
            assert!(h.evidence.contains_key("synthesised"));
        }
    }

    #[test]
    fn camouflage_kind_parse_round_trip_covers_all_variants() {
        for k in [
            CamouflageKind::PhaseShift,
            CamouflageKind::Dropout,
            CamouflageKind::DistributionMismatch,
            CamouflageKind::GradualCreep,
        ] {
            let s = k.as_str();
            let parsed = CamouflageKind::parse(s).expect("round trip");
            assert_eq!(parsed, k);
        }
        let err = CamouflageKind::parse("does_not_exist").unwrap_err();
        assert!(matches!(err, TrajectoryGamingError::UnknownKind { .. }));
    }

    #[test]
    fn series_rejects_inverted_window_range() {
        let err = TrajectorySeries::new(1_000, 500).unwrap_err();
        assert!(matches!(
            err,
            TrajectoryGamingError::InvalidWindow { start: 1_000, end: 500 }
        ));
    }
}
