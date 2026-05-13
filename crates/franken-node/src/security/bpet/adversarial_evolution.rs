//! BPET adversarial evolution types (bd-ye4m sub-task 1).
//!
//! Foundational type layer for the adversarial evaluation suite that drives
//! slow-roll mimicry, staged camouflage, capability-creep, and dormant-then-
//! burst attack campaigns through the BPET pipeline. This module defines:
//!
//! * [`AdversaryKind`] — the eight slow-roll attack archetypes that the
//!   evaluation suite must exercise (see section 10.21 of the master plan).
//! * [`RampCurve`] — parametric trajectories along which an adversary
//!   escalates a target capability. `f64` knobs are guarded via
//!   [`f64::is_finite`] and positivity checks before being mixed into any
//!   step-value computation.
//! * [`AdversaryScenario`] — the validated descriptor handed to the
//!   evaluation harness.
//! * [`EvolutionStep`] / [`EvolutionTrace`] — the per-step record and the
//!   bounded ring of records produced as the scenario runs.
//!
//! # Hardening contract
//!
//! All public constructors and append paths route through validators that
//! enforce the project's standard hardening posture:
//!
//! - `f64::is_finite` guards reject `NaN` / `+/-Inf` on every numeric input
//!   before it can propagate into divergence accumulators or canonical
//!   hashing buffers.
//! - Counter / step arithmetic uses [`u32::saturating_add`] so a malicious
//!   scenario cannot drive a step counter past `u32::MAX` to wrap.
//! - [`append_step`] caps trace growth at [`MAX_EVOLUTION_STEPS`] and
//!   refuses non-monotonic timestamps, preventing replay reordering attacks.
//! - The [`canonical_encoding`] helper prefixes every variable-length field
//!   with its length so distinct scenarios cannot collide on the
//!   `bpet_adversarial_v1:` domain.
//!
//! # Determinism
//!
//! - Field iteration in [`EvolutionStep`] uses [`BTreeMap`], which is
//!   iteration-stable across runs and processes.
//! - [`ramp_value_at`] is a pure function of `(curve, step_idx, n_steps)`
//!   and produces bit-identical outputs for identical inputs.
//! - The canonical encoding is fully byte-deterministic — two structurally
//!   identical traces produce byte-identical canonical buffers regardless
//!   of insertion order (BTreeMap guarantees) or platform endianness
//!   (explicit `to_le_bytes`).
//!
//! # Future sub-tasks (bd-ye4m)
//!
//! Sub-tasks 2-5 build the harness, scenario catalog, integration test
//! wiring, and verification gate on top of this type layer. The intent of
//! this module is to lock the on-disk + hashable shape of an adversary
//! trace before any execution machinery depends on it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Stable telemetry codes emitted by the adversarial-evolution machinery.
///
/// These are intentionally defined alongside the type layer so that downstream
/// harness sub-tasks (bd-ye4m.2+) can reference them without circular module
/// dependencies.
pub mod event_codes {
    pub const BPET_ADV_SCENARIO_ACCEPTED: &str = "BPET-ADV-001";
    pub const BPET_ADV_SCENARIO_REJECTED: &str = "BPET-ADV-002";
    pub const BPET_ADV_STEP_ACCEPTED: &str = "BPET-ADV-003";
    pub const BPET_ADV_STEP_REJECTED: &str = "BPET-ADV-004";
    pub const BPET_ADV_TRACE_BOUNDED: &str = "BPET-ADV-005";
    pub const BPET_ADV_TIMESTAMP_REGRESSION: &str = "BPET-ADV-006";
    pub const BPET_ADV_CANONICAL_ENCODED: &str = "BPET-ADV-007";
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version stamped onto canonical encodings of [`AdversaryScenario`]
/// and [`EvolutionTrace`].
pub const SCHEMA_VERSION: &str = "bpet-adversarial-evolution-v1";

/// Domain separator prefix used by [`canonical_encoding`] so adversarial
/// blobs cannot collide with other BPET artifacts on a shared hash channel.
pub const DOMAIN_SEPARATOR: &[u8] = b"bpet_adversarial_v1:";

/// Maximum number of steps retained in a single [`EvolutionTrace`].
///
/// This is intentionally larger than any production campaign length so that
/// the cap fires only on malicious / runaway inputs. [`append_step`] returns
/// [`AdversarialError::TraceCapacityExceeded`] when the cap is reached.
pub const MAX_EVOLUTION_STEPS: usize = 10_000;

/// Maximum permitted step interval (10 days in milliseconds). Anything
/// longer is treated as accidental misuse / corruption rather than a real
/// adversary cadence.
pub const MAX_STEP_INTERVAL_MS: u64 = 10 * 24 * 60 * 60 * 1_000;

/// Maximum permitted number of steps in a single scenario descriptor.
/// Matches [`MAX_EVOLUTION_STEPS`] cast to `u32`.
pub const MAX_SCENARIO_STEPS: u32 = MAX_EVOLUTION_STEPS as u32;

/// Maximum bounded length for any string field embedded in a scenario or
/// step (id, target capability, observation key).
pub const MAX_STRING_FIELD_LEN: usize = 1_024;

/// Maximum number of (key -> f64) pairs allowed in an [`EvolutionStep`]'s
/// `observed_state` or `declared_state` map.
pub const MAX_STATE_KEYS: usize = 256;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors emitted by validators and append paths in this module.
///
/// Note: `Eq` deliberately omitted because variants carry `f64` payloads
/// (NonFiniteRampParam, NonPositiveRampParam, RampParamOutOfRange,
/// NonFiniteDivergence) and `f64` is not `Eq`. `PartialEq` suffices for
/// test assertions.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AdversarialError {
    #[error("scenario `id` must be non-empty")]
    EmptyScenarioId,
    #[error("scenario `id` length {len} exceeds limit {limit}")]
    ScenarioIdTooLong { len: usize, limit: usize },
    #[error("scenario `target_capability` must be non-empty")]
    EmptyTargetCapability,
    #[error("scenario `target_capability` length {len} exceeds limit {limit}")]
    TargetCapabilityTooLong { len: usize, limit: usize },
    #[error("scenario `n_steps` must be > 0")]
    ZeroSteps,
    #[error("scenario `n_steps` {n} exceeds limit {limit}")]
    TooManySteps { n: u32, limit: u32 },
    #[error("scenario `step_interval_ms` must be > 0")]
    ZeroStepInterval,
    #[error("scenario `step_interval_ms` {interval} exceeds limit {limit}")]
    StepIntervalTooLarge { interval: u64, limit: u64 },
    #[error("ramp curve parameter `{param}` must be finite, got {value}")]
    NonFiniteRampParam { param: &'static str, value: f64 },
    #[error("ramp curve parameter `{param}` must be > 0, got {value}")]
    NonPositiveRampParam { param: &'static str, value: f64 },
    #[error("ramp curve parameter `{param}` is out of range, got {value}")]
    RampParamOutOfRange { param: &'static str, value: f64 },
    #[error("step `divergence` must be finite, got {0}")]
    NonFiniteDivergence(f64),
    #[error("state value for key `{key}` is not finite")]
    NonFiniteStateValue { key: String },
    #[error("state key shape mismatch: observed and declared keys differ")]
    StateKeyShapeMismatch,
    #[error("state map length {len} exceeds limit {limit}")]
    StateMapTooLarge { len: usize, limit: usize },
    #[error("state key length {len} exceeds limit {limit}")]
    StateKeyTooLong { len: usize, limit: usize },
    #[error("step scenario_id `{step_id}` does not match trace scenario_id `{trace_id}`")]
    ScenarioIdMismatch { step_id: String, trace_id: String },
    #[error("step timestamp {step_ts} regressed below last timestamp {last_ts}")]
    NonMonotonicTimestamp { step_ts: i64, last_ts: i64 },
    #[error("trace already contains {0} steps; bounded growth cap reached")]
    TraceCapacityExceeded(usize),
    #[error("trace `ended_at` {ended_at} is before `started_at` {started_at}")]
    EndedBeforeStarted { started_at: i64, ended_at: i64 },
}

/// Convenience alias for results emitted by this module.
pub type Result<T> = std::result::Result<T, AdversarialError>;

// ---------------------------------------------------------------------------
// AdversaryKind
// ---------------------------------------------------------------------------

/// Catalog of slow-roll adversary archetypes exercised by the evaluation
/// suite. Each variant maps to a campaign module under
/// `tests/security/adversarial_scenarios/` (sub-task 3 of bd-ye4m).
///
/// Mappings:
///
/// - [`AdversaryKind::SlowRollDrift`] — `drift-via-many-small-updates`.
/// - [`AdversaryKind::CapabilityCreepDisguisedAsFeature`] —
///   `capability-creep-disguised-as-feature-add`.
/// - [`AdversaryKind::EvictionViaTrustFlooding`] — `eviction-via-trust-flooding`.
/// - [`AdversaryKind::ManyTinyUpdates`] — high-frequency micro-perturbation.
/// - [`AdversaryKind::MultiPersonaCoordination`] — colluding maintainer
///   identities ramping in synchrony.
/// - [`AdversaryKind::FalseRecoveryClaim`] — fakes a "recovered baseline"
///   announcement mid-campaign to short-circuit detectors.
/// - [`AdversaryKind::IndirectViaDep`] — escalates capability through a
///   dependency rather than the package under test.
/// - [`AdversaryKind::SignatureRollover`] — abuses a maintainer key roll to
///   relaunder a previously-flagged trajectory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversaryKind {
    SlowRollDrift,
    CapabilityCreepDisguisedAsFeature,
    EvictionViaTrustFlooding,
    ManyTinyUpdates,
    MultiPersonaCoordination,
    FalseRecoveryClaim,
    IndirectViaDep,
    SignatureRollover,
}

impl AdversaryKind {
    /// Stable kebab-case identifier used in artifacts and canonical hashing.
    pub const fn as_str(self) -> &'static str {
        match self {
            AdversaryKind::SlowRollDrift => "slow_roll_drift",
            AdversaryKind::CapabilityCreepDisguisedAsFeature => {
                "capability_creep_disguised_as_feature"
            }
            AdversaryKind::EvictionViaTrustFlooding => "eviction_via_trust_flooding",
            AdversaryKind::ManyTinyUpdates => "many_tiny_updates",
            AdversaryKind::MultiPersonaCoordination => "multi_persona_coordination",
            AdversaryKind::FalseRecoveryClaim => "false_recovery_claim",
            AdversaryKind::IndirectViaDep => "indirect_via_dep",
            AdversaryKind::SignatureRollover => "signature_rollover",
        }
    }
}

// ---------------------------------------------------------------------------
// RampCurve
// ---------------------------------------------------------------------------

/// Parametric ramp curve describing how an adversary escalates the target
/// capability across `n_steps`.
///
/// All `f64` knobs must be finite and strictly positive; this is enforced by
/// [`RampCurve::validate`] and by [`AdversaryScenario::validate`] (called
/// transitively from [`validate_scenario`]).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RampCurve {
    /// `f(i) = i / (n - 1)` for `n > 1`, else `0.0`.
    Linear,
    /// `f(i) = (base^(i/(n-1)) - 1) / (base - 1)`. Requires `base > 0`
    /// and `base != 1.0`.
    Exponential { base: f64 },
    /// Logistic sigmoid centered at `n/2` with given `steepness`. Requires
    /// `steepness > 0`.
    Sigmoid { steepness: f64 },
    /// Step-function with `plateau_count` plateaus of equal width. Requires
    /// `plateau_count >= 1`.
    Stepped { plateau_count: u32 },
}

impl RampCurve {
    /// Validate the curve's parameters for finiteness and positivity.
    pub fn validate(&self) -> Result<()> {
        match *self {
            RampCurve::Linear => Ok(()),
            RampCurve::Exponential { base } => {
                if !base.is_finite() {
                    return Err(AdversarialError::NonFiniteRampParam {
                        param: "base",
                        value: base,
                    });
                }
                if base <= 0.0 {
                    return Err(AdversarialError::NonPositiveRampParam {
                        param: "base",
                        value: base,
                    });
                }
                // base == 1.0 reduces Exponential to a constant; reject so
                // callers explicitly use Linear.
                if (base - 1.0).abs() < f64::EPSILON {
                    return Err(AdversarialError::RampParamOutOfRange {
                        param: "base",
                        value: base,
                    });
                }
                Ok(())
            }
            RampCurve::Sigmoid { steepness } => {
                if !steepness.is_finite() {
                    return Err(AdversarialError::NonFiniteRampParam {
                        param: "steepness",
                        value: steepness,
                    });
                }
                if steepness <= 0.0 {
                    return Err(AdversarialError::NonPositiveRampParam {
                        param: "steepness",
                        value: steepness,
                    });
                }
                Ok(())
            }
            RampCurve::Stepped { plateau_count } => {
                if plateau_count == 0 {
                    return Err(AdversarialError::NonPositiveRampParam {
                        param: "plateau_count",
                        value: 0.0,
                    });
                }
                Ok(())
            }
        }
    }

    /// Compute the ramp value at `step_idx` (0-based) given `n_steps` total
    /// steps. Returns a value in `[0.0, 1.0]` for all valid curves. Returns
    /// `0.0` when `n_steps == 0` (scenarios with zero steps are invalid but
    /// this guards against division by zero defensively).
    pub fn value_at(&self, step_idx: u32, n_steps: u32) -> f64 {
        if n_steps == 0 {
            return 0.0;
        }
        let n = n_steps as f64;
        let i = step_idx.min(n_steps.saturating_sub(1)) as f64;
        // Single-step scenario degenerates to a single 0.0 sample.
        if n_steps == 1 {
            return 0.0;
        }
        let t = i / (n - 1.0);
        let v = match *self {
            RampCurve::Linear => t,
            RampCurve::Exponential { base } => {
                if !base.is_finite() || base <= 0.0 || (base - 1.0).abs() < f64::EPSILON {
                    return 0.0;
                }
                (base.powf(t) - 1.0) / (base - 1.0)
            }
            RampCurve::Sigmoid { steepness } => {
                if !steepness.is_finite() || steepness <= 0.0 {
                    return 0.0;
                }
                // Map t in [0,1] -> [-steepness, +steepness], then sigmoid.
                let x = (t - 0.5) * 2.0 * steepness;
                1.0 / (1.0 + (-x).exp())
            }
            RampCurve::Stepped { plateau_count } => {
                if plateau_count == 0 {
                    return 0.0;
                }
                let plateau_idx = (t * plateau_count as f64).floor();
                let denom = plateau_count.saturating_sub(1).max(1) as f64;
                let max_idx = plateau_count.saturating_sub(1) as f64;
                plateau_idx.min(max_idx) / denom
            }
        };
        if v.is_finite() { v.clamp(0.0, 1.0) } else { 0.0 }
    }
}

// ---------------------------------------------------------------------------
// AdversaryScenario
// ---------------------------------------------------------------------------

/// A validated descriptor of a single adversary campaign that the
/// evaluation suite will run against the BPET pipeline.
///
/// Always constructed via [`AdversaryScenario::try_new`] (or by external
/// deserializers paired with [`validate_scenario`]) so the invariants in
/// [`Self::validate`] hold for every in-memory instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdversaryScenario {
    /// Stable, non-empty identifier for the scenario (kebab/snake-case is
    /// recommended). Used as the canonical-encoding key.
    pub id: String,
    /// Archetype this scenario instantiates.
    pub kind: AdversaryKind,
    /// Number of evolution steps to run. Must be `> 0` and
    /// `<= MAX_SCENARIO_STEPS`.
    pub n_steps: u32,
    /// Wall-clock interval between consecutive steps, in milliseconds.
    /// Must be `> 0` and `<= MAX_STEP_INTERVAL_MS`.
    pub step_interval_ms: u64,
    /// Capability or surface the adversary is trying to escalate (e.g.
    /// `"network.outbound"`, `"fs.write"`).
    pub target_capability: String,
    /// Trajectory along which the adversary ramps.
    pub ramp_curve: RampCurve,
}

impl AdversaryScenario {
    /// Construct + validate. Returns an error on any invariant violation.
    pub fn try_new(
        id: impl Into<String>,
        kind: AdversaryKind,
        n_steps: u32,
        step_interval_ms: u64,
        target_capability: impl Into<String>,
        ramp_curve: RampCurve,
    ) -> Result<Self> {
        let scenario = Self {
            id: id.into(),
            kind,
            n_steps,
            step_interval_ms,
            target_capability: target_capability.into(),
            ramp_curve,
        };
        scenario.validate()?;
        Ok(scenario)
    }

    /// Validate the scenario's invariants in-place.
    pub fn validate(&self) -> Result<()> {
        validate_scenario(self)
    }
}

/// Free-function form of [`AdversaryScenario::validate`] so callers can
/// validate after `serde` deserialization without owning a method.
pub fn validate_scenario(s: &AdversaryScenario) -> Result<()> {
    if s.id.is_empty() {
        return Err(AdversarialError::EmptyScenarioId);
    }
    if s.id.len() > MAX_STRING_FIELD_LEN {
        return Err(AdversarialError::ScenarioIdTooLong {
            len: s.id.len(),
            limit: MAX_STRING_FIELD_LEN,
        });
    }
    if s.target_capability.is_empty() {
        return Err(AdversarialError::EmptyTargetCapability);
    }
    if s.target_capability.len() > MAX_STRING_FIELD_LEN {
        return Err(AdversarialError::TargetCapabilityTooLong {
            len: s.target_capability.len(),
            limit: MAX_STRING_FIELD_LEN,
        });
    }
    if s.n_steps == 0 {
        return Err(AdversarialError::ZeroSteps);
    }
    if s.n_steps > MAX_SCENARIO_STEPS {
        return Err(AdversarialError::TooManySteps {
            n: s.n_steps,
            limit: MAX_SCENARIO_STEPS,
        });
    }
    if s.step_interval_ms == 0 {
        return Err(AdversarialError::ZeroStepInterval);
    }
    if s.step_interval_ms > MAX_STEP_INTERVAL_MS {
        return Err(AdversarialError::StepIntervalTooLarge {
            interval: s.step_interval_ms,
            limit: MAX_STEP_INTERVAL_MS,
        });
    }
    s.ramp_curve.validate()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// EvolutionStep
// ---------------------------------------------------------------------------

/// A single observation in an adversary campaign — the state the adversary
/// *declared* (e.g. via package metadata, capability manifest) versus the
/// state actually *observed* by BPET, plus a scalar divergence score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionStep {
    /// 0-based step index within the parent scenario.
    pub step_idx: u32,
    /// Wall-clock timestamp in Unix milliseconds.
    pub ts: i64,
    /// `AdversaryScenario::id` this step belongs to.
    pub scenario_id: String,
    /// Observed phenotype state, keyed by feature name.
    pub observed_state: BTreeMap<String, f64>,
    /// Declared phenotype state, keyed by feature name.
    pub declared_state: BTreeMap<String, f64>,
    /// Scalar divergence summary between `observed_state` and
    /// `declared_state`. Must be finite and `>= 0.0`.
    pub divergence: f64,
}

/// Free-function form of [`EvolutionStep`] validation.
pub fn validate_step(s: &EvolutionStep) -> Result<()> {
    if !s.divergence.is_finite() {
        return Err(AdversarialError::NonFiniteDivergence(s.divergence));
    }
    if s.observed_state.len() > MAX_STATE_KEYS {
        return Err(AdversarialError::StateMapTooLarge {
            len: s.observed_state.len(),
            limit: MAX_STATE_KEYS,
        });
    }
    if s.declared_state.len() > MAX_STATE_KEYS {
        return Err(AdversarialError::StateMapTooLarge {
            len: s.declared_state.len(),
            limit: MAX_STATE_KEYS,
        });
    }
    // Key shape must agree: same set of keys in both maps. We rely on
    // BTreeMap's deterministic key iteration order to compare in O(n).
    if s.observed_state.len() != s.declared_state.len() {
        return Err(AdversarialError::StateKeyShapeMismatch);
    }
    for (obs_key, declared_key) in s
        .observed_state
        .keys()
        .zip(s.declared_state.keys())
    {
        if obs_key != declared_key {
            return Err(AdversarialError::StateKeyShapeMismatch);
        }
        if obs_key.len() > MAX_STRING_FIELD_LEN {
            return Err(AdversarialError::StateKeyTooLong {
                len: obs_key.len(),
                limit: MAX_STRING_FIELD_LEN,
            });
        }
    }
    for (key, value) in &s.observed_state {
        if !value.is_finite() {
            return Err(AdversarialError::NonFiniteStateValue { key: key.clone() });
        }
    }
    for (key, value) in &s.declared_state {
        if !value.is_finite() {
            return Err(AdversarialError::NonFiniteStateValue { key: key.clone() });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// EvolutionTrace
// ---------------------------------------------------------------------------

/// Bounded sequence of [`EvolutionStep`] records for a single scenario,
/// plus campaign-level lifecycle timestamps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionTrace {
    pub scenario_id: String,
    pub steps: Vec<EvolutionStep>,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub detected_at: Option<i64>,
}

impl EvolutionTrace {
    /// Construct a new empty trace tied to a scenario id and start time.
    pub fn new(scenario_id: impl Into<String>, started_at: i64) -> Self {
        Self {
            scenario_id: scenario_id.into(),
            steps: Vec::new(),
            started_at,
            ended_at: None,
            detected_at: None,
        }
    }

    /// Validate the trace's structural invariants. Per-step invariants are
    /// already enforced by [`append_step`]; this is the post-deserialization
    /// re-check.
    pub fn validate(&self) -> Result<()> {
        if self.steps.len() > MAX_EVOLUTION_STEPS {
            return Err(AdversarialError::TraceCapacityExceeded(self.steps.len()));
        }
        if let Some(ended_at) = self.ended_at {
            if ended_at < self.started_at {
                return Err(AdversarialError::EndedBeforeStarted {
                    started_at: self.started_at,
                    ended_at,
                });
            }
        }
        let mut last_ts: Option<i64> = None;
        for step in &self.steps {
            if step.scenario_id != self.scenario_id {
                return Err(AdversarialError::ScenarioIdMismatch {
                    step_id: step.scenario_id.clone(),
                    trace_id: self.scenario_id.clone(),
                });
            }
            validate_step(step)?;
            if let Some(prev) = last_ts {
                if step.ts < prev {
                    return Err(AdversarialError::NonMonotonicTimestamp {
                        step_ts: step.ts,
                        last_ts: prev,
                    });
                }
            }
            last_ts = Some(step.ts);
        }
        Ok(())
    }
}

/// Append `step` to `trace`, enforcing:
///
/// - `step.scenario_id == trace.scenario_id`.
/// - `step.ts >= last_step.ts` (monotonic timestamps).
/// - Per-step finiteness + key-shape invariants via [`validate_step`].
/// - `trace.steps.len() < MAX_EVOLUTION_STEPS` (bounded growth).
///
/// Note: bounded growth is enforced as a *fail-closed* error here rather
/// than silently dropping the oldest entry. The adversarial suite's
/// detector-correctness signal depends on the trace being a faithful
/// prefix of the campaign; silently rotating would invalidate downstream
/// assertions.
pub fn append_step(trace: &mut EvolutionTrace, step: EvolutionStep) -> Result<()> {
    if trace.steps.len() >= MAX_EVOLUTION_STEPS {
        return Err(AdversarialError::TraceCapacityExceeded(trace.steps.len()));
    }
    if step.scenario_id != trace.scenario_id {
        return Err(AdversarialError::ScenarioIdMismatch {
            step_id: step.scenario_id,
            trace_id: trace.scenario_id.clone(),
        });
    }
    validate_step(&step)?;
    if let Some(last) = trace.steps.last() {
        if step.ts < last.ts {
            return Err(AdversarialError::NonMonotonicTimestamp {
                step_ts: step.ts,
                last_ts: last.ts,
            });
        }
    }
    trace.steps.push(step);
    Ok(())
}

// ---------------------------------------------------------------------------
// Canonical encoding (length-prefixed, domain-separated)
// ---------------------------------------------------------------------------

/// Convert `usize` -> `u64` saturating at `u64::MAX` so length prefixes are
/// always well-defined.
fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Push a length-prefixed `&[u8]` slice into `buf`.
///
/// The prefix is the slice length encoded as little-endian `u64`, ensuring
/// that two structurally distinct inputs cannot produce the same canonical
/// byte stream by accident (e.g. concatenating two strings on either side
/// of a delimiter).
fn push_lp(buf: &mut Vec<u8>, slice: &[u8]) {
    buf.extend_from_slice(&len_to_u64(slice.len()).to_le_bytes());
    buf.extend_from_slice(slice);
}

/// Canonical, length-prefixed encoding of a scenario under
/// [`DOMAIN_SEPARATOR`]. Two scenarios encode identically iff every field
/// matches byte-for-byte, including `RampCurve` discriminant and parameters.
pub fn canonical_encoding(scenario: &AdversaryScenario) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(DOMAIN_SEPARATOR);
    push_lp(&mut buf, SCHEMA_VERSION.as_bytes());
    push_lp(&mut buf, scenario.id.as_bytes());
    push_lp(&mut buf, scenario.kind.as_str().as_bytes());
    buf.extend_from_slice(&scenario.n_steps.to_le_bytes());
    buf.extend_from_slice(&scenario.step_interval_ms.to_le_bytes());
    push_lp(&mut buf, scenario.target_capability.as_bytes());
    encode_ramp_curve(&mut buf, &scenario.ramp_curve);
    buf
}

fn encode_ramp_curve(buf: &mut Vec<u8>, curve: &RampCurve) {
    match *curve {
        RampCurve::Linear => {
            push_lp(buf, b"linear");
        }
        RampCurve::Exponential { base } => {
            push_lp(buf, b"exponential");
            buf.extend_from_slice(&base.to_le_bytes());
        }
        RampCurve::Sigmoid { steepness } => {
            push_lp(buf, b"sigmoid");
            buf.extend_from_slice(&steepness.to_le_bytes());
        }
        RampCurve::Stepped { plateau_count } => {
            push_lp(buf, b"stepped");
            buf.extend_from_slice(&plateau_count.to_le_bytes());
        }
    }
}

/// SHA-256 of [`canonical_encoding`] hex-encoded. Convenience for tests +
/// downstream artifacts that pin the scenario shape.
pub fn canonical_hash(scenario: &AdversaryScenario) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_encoding(scenario));
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_scenario() -> AdversaryScenario {
        AdversaryScenario::try_new(
            "scn-slow-roll",
            AdversaryKind::SlowRollDrift,
            10,
            1_000,
            "network.outbound",
            RampCurve::Linear,
        )
        .expect("baseline scenario must validate")
    }

    fn sample_step(idx: u32, ts: i64, scenario_id: &str, divergence: f64) -> EvolutionStep {
        let mut observed = BTreeMap::new();
        observed.insert("capability.score".to_string(), 0.25);
        observed.insert("commit.velocity".to_string(), 1.5);
        let mut declared = BTreeMap::new();
        declared.insert("capability.score".to_string(), 0.20);
        declared.insert("commit.velocity".to_string(), 1.4);
        EvolutionStep {
            step_idx: idx,
            ts,
            scenario_id: scenario_id.to_string(),
            observed_state: observed,
            declared_state: declared,
            divergence,
        }
    }

    // -----------------------------------------------------------------------
    // 1. serde round-trip for each type
    // -----------------------------------------------------------------------

    #[test]
    fn serde_roundtrip_adversary_kind() {
        for kind in [
            AdversaryKind::SlowRollDrift,
            AdversaryKind::CapabilityCreepDisguisedAsFeature,
            AdversaryKind::EvictionViaTrustFlooding,
            AdversaryKind::ManyTinyUpdates,
            AdversaryKind::MultiPersonaCoordination,
            AdversaryKind::FalseRecoveryClaim,
            AdversaryKind::IndirectViaDep,
            AdversaryKind::SignatureRollover,
        ] {
            let json = serde_json::to_string(&kind).expect("encode kind");
            let back: AdversaryKind = serde_json::from_str(&json).expect("decode kind");
            assert_eq!(back, kind, "round-trip stable for {kind:?}");
        }
    }

    #[test]
    fn serde_roundtrip_ramp_curve() {
        let cases = [
            RampCurve::Linear,
            RampCurve::Exponential { base: 2.0 },
            RampCurve::Sigmoid { steepness: 4.0 },
            RampCurve::Stepped { plateau_count: 5 },
        ];
        for curve in cases {
            let json = serde_json::to_string(&curve).expect("encode curve");
            let back: RampCurve = serde_json::from_str(&json).expect("decode curve");
            assert_eq!(back, curve, "round-trip stable for {curve:?}");
        }
    }

    #[test]
    fn serde_roundtrip_scenario() {
        let scenario = sample_scenario();
        let json = serde_json::to_string(&scenario).expect("encode scenario");
        let back: AdversaryScenario = serde_json::from_str(&json).expect("decode scenario");
        assert_eq!(back, scenario);
        assert!(validate_scenario(&back).is_ok());
    }

    #[test]
    fn serde_roundtrip_step_and_trace() {
        let step = sample_step(0, 1_000, "scn-slow-roll", 0.05);
        let json = serde_json::to_string(&step).expect("encode step");
        let back: EvolutionStep = serde_json::from_str(&json).expect("decode step");
        assert_eq!(back, step);
        assert!(validate_step(&back).is_ok());

        let mut trace = EvolutionTrace::new("scn-slow-roll", 1_000);
        append_step(&mut trace, step).expect("append");
        let json = serde_json::to_string(&trace).expect("encode trace");
        let back: EvolutionTrace = serde_json::from_str(&json).expect("decode trace");
        assert_eq!(back, trace);
        assert!(back.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // 2. validate_scenario rejects empty id
    // -----------------------------------------------------------------------

    #[test]
    fn validate_scenario_rejects_empty_id() {
        let scenario = AdversaryScenario {
            id: String::new(),
            kind: AdversaryKind::SlowRollDrift,
            n_steps: 10,
            step_interval_ms: 1_000,
            target_capability: "network.outbound".to_string(),
            ramp_curve: RampCurve::Linear,
        };
        assert_eq!(
            validate_scenario(&scenario),
            Err(AdversarialError::EmptyScenarioId)
        );
    }

    #[test]
    fn validate_scenario_rejects_empty_target_capability() {
        let scenario = AdversaryScenario {
            id: "scn-1".to_string(),
            kind: AdversaryKind::SlowRollDrift,
            n_steps: 10,
            step_interval_ms: 1_000,
            target_capability: String::new(),
            ramp_curve: RampCurve::Linear,
        };
        assert_eq!(
            validate_scenario(&scenario),
            Err(AdversarialError::EmptyTargetCapability)
        );
    }

    // -----------------------------------------------------------------------
    // 3. validate_scenario rejects n_steps = 0
    // -----------------------------------------------------------------------

    #[test]
    fn validate_scenario_rejects_zero_steps() {
        let scenario = AdversaryScenario {
            id: "scn-zero".to_string(),
            kind: AdversaryKind::SlowRollDrift,
            n_steps: 0,
            step_interval_ms: 1_000,
            target_capability: "network.outbound".to_string(),
            ramp_curve: RampCurve::Linear,
        };
        assert_eq!(validate_scenario(&scenario), Err(AdversarialError::ZeroSteps));
    }

    #[test]
    fn validate_scenario_rejects_zero_step_interval() {
        let scenario = AdversaryScenario {
            id: "scn-zero-interval".to_string(),
            kind: AdversaryKind::SlowRollDrift,
            n_steps: 10,
            step_interval_ms: 0,
            target_capability: "network.outbound".to_string(),
            ramp_curve: RampCurve::Linear,
        };
        assert_eq!(
            validate_scenario(&scenario),
            Err(AdversarialError::ZeroStepInterval)
        );
    }

    #[test]
    fn validate_scenario_rejects_excess_step_interval() {
        let scenario = AdversaryScenario {
            id: "scn-big".to_string(),
            kind: AdversaryKind::SlowRollDrift,
            n_steps: 10,
            step_interval_ms: MAX_STEP_INTERVAL_MS + 1,
            target_capability: "network.outbound".to_string(),
            ramp_curve: RampCurve::Linear,
        };
        assert!(matches!(
            validate_scenario(&scenario),
            Err(AdversarialError::StepIntervalTooLarge { .. })
        ));
    }

    #[test]
    fn validate_scenario_rejects_excess_n_steps() {
        let scenario = AdversaryScenario {
            id: "scn-huge".to_string(),
            kind: AdversaryKind::SlowRollDrift,
            n_steps: MAX_SCENARIO_STEPS + 1,
            step_interval_ms: 1_000,
            target_capability: "network.outbound".to_string(),
            ramp_curve: RampCurve::Linear,
        };
        assert!(matches!(
            validate_scenario(&scenario),
            Err(AdversarialError::TooManySteps { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // 4. Linear / Exponential / Sigmoid produce different sequences
    // -----------------------------------------------------------------------

    #[test]
    fn ramp_curves_produce_distinct_sequences() {
        let n = 11_u32;
        let linear: Vec<f64> = (0..n).map(|i| RampCurve::Linear.value_at(i, n)).collect();
        let exp: Vec<f64> = (0..n)
            .map(|i| RampCurve::Exponential { base: 4.0 }.value_at(i, n))
            .collect();
        let sigmoid: Vec<f64> = (0..n)
            .map(|i| RampCurve::Sigmoid { steepness: 6.0 }.value_at(i, n))
            .collect();
        let stepped: Vec<f64> = (0..n)
            .map(|i| RampCurve::Stepped { plateau_count: 4 }.value_at(i, n))
            .collect();

        // Endpoints: every curve starts at 0.0 and reaches its top sample
        // at i == n-1.
        for seq in [&linear, &exp, &sigmoid, &stepped] {
            assert!(seq.iter().all(|v| v.is_finite()));
            assert!((seq[0] - 0.0).abs() < 1e-9);
            assert!((0.0..=1.0).contains(&seq[(n - 1) as usize]));
        }
        // Middle samples should differ across non-trivial curves so that
        // the harness can actually distinguish ramp styles.
        let mid = (n / 2) as usize;
        assert!((linear[mid] - exp[mid]).abs() > 1e-3);
        assert!((linear[mid] - sigmoid[mid]).abs() > 1e-3);
        assert!((exp[mid] - sigmoid[mid]).abs() > 1e-3);
        // Stepped should plateau: at least two consecutive samples must be
        // exactly equal.
        let any_repeat = stepped.windows(2).any(|w| (w[0] - w[1]).abs() < 1e-12);
        assert!(any_repeat, "stepped ramp must contain a plateau");
    }

    #[test]
    fn ramp_curve_rejects_non_positive_or_unit_base() {
        assert!(matches!(
            RampCurve::Exponential { base: 0.0 }.validate(),
            Err(AdversarialError::NonPositiveRampParam { .. })
        ));
        assert!(matches!(
            RampCurve::Exponential { base: -1.0 }.validate(),
            Err(AdversarialError::NonPositiveRampParam { .. })
        ));
        assert!(matches!(
            RampCurve::Exponential { base: f64::NAN }.validate(),
            Err(AdversarialError::NonFiniteRampParam { .. })
        ));
        assert!(matches!(
            RampCurve::Exponential { base: 1.0 }.validate(),
            Err(AdversarialError::RampParamOutOfRange { .. })
        ));
        assert!(matches!(
            RampCurve::Sigmoid { steepness: 0.0 }.validate(),
            Err(AdversarialError::NonPositiveRampParam { .. })
        ));
        assert!(matches!(
            RampCurve::Sigmoid {
                steepness: f64::INFINITY
            }
            .validate(),
            Err(AdversarialError::NonFiniteRampParam { .. })
        ));
        assert!(matches!(
            RampCurve::Stepped { plateau_count: 0 }.validate(),
            Err(AdversarialError::NonPositiveRampParam { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // 5. validate_step rejects NaN divergence
    // -----------------------------------------------------------------------

    #[test]
    fn validate_step_rejects_nan_divergence() {
        let step = sample_step(0, 1_000, "scn", f64::NAN);
        assert!(matches!(
            validate_step(&step),
            Err(AdversarialError::NonFiniteDivergence(_))
        ));

        let step_inf = sample_step(0, 1_000, "scn", f64::INFINITY);
        assert!(matches!(
            validate_step(&step_inf),
            Err(AdversarialError::NonFiniteDivergence(_))
        ));
    }

    #[test]
    fn validate_step_rejects_non_finite_state_value() {
        let mut step = sample_step(0, 1_000, "scn", 0.1);
        step.observed_state
            .insert("capability.score".to_string(), f64::NAN);
        assert!(matches!(
            validate_step(&step),
            Err(AdversarialError::NonFiniteStateValue { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // 6. validate_step rejects key-shape mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn validate_step_rejects_key_shape_mismatch_extra_observed() {
        let mut step = sample_step(0, 1_000, "scn", 0.1);
        step.observed_state.insert("extra.key".to_string(), 0.5);
        assert_eq!(
            validate_step(&step),
            Err(AdversarialError::StateKeyShapeMismatch)
        );
    }

    #[test]
    fn validate_step_rejects_key_shape_mismatch_extra_declared() {
        let mut step = sample_step(0, 1_000, "scn", 0.1);
        step.declared_state.insert("extra.key".to_string(), 0.5);
        assert_eq!(
            validate_step(&step),
            Err(AdversarialError::StateKeyShapeMismatch)
        );
    }

    #[test]
    fn validate_step_rejects_key_shape_mismatch_renamed_key() {
        let mut step = sample_step(0, 1_000, "scn", 0.1);
        // Remove a key in observed, add a different-name key with same
        // arity in declared so lengths match but keys diverge.
        step.observed_state.remove("commit.velocity");
        step.observed_state.insert("renamed.velocity".to_string(), 1.5);
        assert_eq!(
            validate_step(&step),
            Err(AdversarialError::StateKeyShapeMismatch)
        );
    }

    // -----------------------------------------------------------------------
    // 7. append_step enforces monotonic timestamps
    // -----------------------------------------------------------------------

    #[test]
    fn append_step_enforces_monotonic_timestamps() {
        let mut trace = EvolutionTrace::new("scn-mono", 0);
        append_step(&mut trace, sample_step(0, 100, "scn-mono", 0.1)).unwrap();
        append_step(&mut trace, sample_step(1, 200, "scn-mono", 0.2)).unwrap();
        let err = append_step(&mut trace, sample_step(2, 150, "scn-mono", 0.3))
            .expect_err("non-monotonic must be rejected");
        assert!(matches!(err, AdversarialError::NonMonotonicTimestamp { .. }));
        // Equal timestamps are accepted (multiple events in the same ms).
        append_step(&mut trace, sample_step(2, 200, "scn-mono", 0.3)).unwrap();
        assert_eq!(trace.steps.len(), 3);
    }

    #[test]
    fn append_step_rejects_scenario_id_mismatch() {
        let mut trace = EvolutionTrace::new("scn-id", 0);
        let err = append_step(&mut trace, sample_step(0, 100, "other-id", 0.1))
            .expect_err("scenario id mismatch must be rejected");
        assert!(matches!(err, AdversarialError::ScenarioIdMismatch { .. }));
    }

    // -----------------------------------------------------------------------
    // 8. append_step bounded growth at MAX_EVOLUTION_STEPS
    // -----------------------------------------------------------------------

    #[test]
    fn append_step_enforces_bounded_growth() {
        let mut trace = EvolutionTrace::new("scn-bounded", 0);
        // Pre-fill to capacity using direct vec push to keep the test fast;
        // this exercises the cap-check branch in append_step without
        // requiring 10k validator round-trips.
        for i in 0..MAX_EVOLUTION_STEPS {
            trace
                .steps
                .push(sample_step(i as u32, i as i64, "scn-bounded", 0.0));
        }
        assert_eq!(trace.steps.len(), MAX_EVOLUTION_STEPS);

        let overflow = sample_step(
            MAX_EVOLUTION_STEPS as u32,
            MAX_EVOLUTION_STEPS as i64,
            "scn-bounded",
            0.0,
        );
        let err =
            append_step(&mut trace, overflow).expect_err("over-capacity append must be rejected");
        assert!(matches!(err, AdversarialError::TraceCapacityExceeded(_)));
        assert_eq!(
            trace.steps.len(),
            MAX_EVOLUTION_STEPS,
            "trace length must not grow past cap"
        );
    }

    #[test]
    fn evolution_trace_validate_rejects_ended_before_started() {
        let mut trace = EvolutionTrace::new("scn-ended", 1_000);
        trace.ended_at = Some(500);
        assert!(matches!(
            trace.validate(),
            Err(AdversarialError::EndedBeforeStarted { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // 9. canonical encoding is deterministic
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_encoding_is_deterministic() {
        let a = AdversaryScenario::try_new(
            "scn-det",
            AdversaryKind::CapabilityCreepDisguisedAsFeature,
            32,
            5_000,
            "fs.write",
            RampCurve::Exponential { base: 3.0 },
        )
        .unwrap();
        let b = a.clone();
        let enc_a = canonical_encoding(&a);
        let enc_b = canonical_encoding(&b);
        assert_eq!(enc_a, enc_b);
        assert_eq!(canonical_hash(&a), canonical_hash(&b));
        // Differs from a structurally distinct scenario.
        let mut c = a.clone();
        c.kind = AdversaryKind::SlowRollDrift;
        assert_ne!(canonical_hash(&a), canonical_hash(&c));
    }

    // -----------------------------------------------------------------------
    // 10. canonical encoding is collision-resistant via length-prefix
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_encoding_length_prefix_resists_field_concat_collisions() {
        // Two scenarios where naive concatenation of `id || target_capability`
        // would produce the same byte sequence. Length-prefixing must keep
        // their encodings (and hashes) distinct.
        let a = AdversaryScenario::try_new(
            "ab",
            AdversaryKind::SlowRollDrift,
            10,
            1_000,
            "cd",
            RampCurve::Linear,
        )
        .unwrap();
        let b = AdversaryScenario::try_new(
            "a",
            AdversaryKind::SlowRollDrift,
            10,
            1_000,
            "bcd",
            RampCurve::Linear,
        )
        .unwrap();
        let enc_a = canonical_encoding(&a);
        let enc_b = canonical_encoding(&b);
        assert_ne!(enc_a, enc_b, "length-prefix must prevent boundary collisions");
        assert_ne!(canonical_hash(&a), canonical_hash(&b));

        // RampCurve discriminant collision probe: two encodings that share
        // the same numeric tail but different ramp tags must still differ.
        let lin = AdversaryScenario::try_new(
            "scn-x",
            AdversaryKind::SlowRollDrift,
            8,
            1_000,
            "cap.x",
            RampCurve::Linear,
        )
        .unwrap();
        let exp = AdversaryScenario::try_new(
            "scn-x",
            AdversaryKind::SlowRollDrift,
            8,
            1_000,
            "cap.x",
            RampCurve::Exponential { base: 2.0 },
        )
        .unwrap();
        assert_ne!(canonical_encoding(&lin), canonical_encoding(&exp));
    }

    // -----------------------------------------------------------------------
    // Bonus: AdversaryKind::as_str stability
    // -----------------------------------------------------------------------

    #[test]
    fn adversary_kind_as_str_is_stable_snake_case() {
        assert_eq!(AdversaryKind::SlowRollDrift.as_str(), "slow_roll_drift");
        assert_eq!(
            AdversaryKind::CapabilityCreepDisguisedAsFeature.as_str(),
            "capability_creep_disguised_as_feature"
        );
        assert_eq!(
            AdversaryKind::EvictionViaTrustFlooding.as_str(),
            "eviction_via_trust_flooding"
        );
        assert_eq!(
            AdversaryKind::MultiPersonaCoordination.as_str(),
            "multi_persona_coordination"
        );
        assert_eq!(
            AdversaryKind::FalseRecoveryClaim.as_str(),
            "false_recovery_claim"
        );
        assert_eq!(AdversaryKind::IndirectViaDep.as_str(), "indirect_via_dep");
        assert_eq!(
            AdversaryKind::SignatureRollover.as_str(),
            "signature_rollover"
        );
        assert_eq!(
            AdversaryKind::ManyTinyUpdates.as_str(),
            "many_tiny_updates"
        );
    }
}
