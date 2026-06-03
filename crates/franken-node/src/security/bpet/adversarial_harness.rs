//! BPET adversarial evaluation harness (bd-ye4m sub-task 2).
//!
//! Drives an [`AdversaryScenario`] through the existing BPET drift + risk
//! scoring pipeline and captures per-step behavior, producing an
//! [`EvolutionResult`] that downstream sub-tasks (3 = scenario catalog,
//! 4 = integration assertions, 5 = verification gate) can pin against
//! deterministic outcomes.
//!
//! The harness is intentionally implemented as a **public library module**
//! rather than as the eventual `tests/security/bpet_adversarial_evolution_suite.rs`
//! file. The plan calls for that integration-test file to exist; this module
//! is the load-bearing logic the integration test will call into. Splitting
//! responsibility this way keeps the harness compilable inside the main
//! crate (so other modules can re-use it for fuzz harnesses, replay
//! fixtures, and the verification gate in sub-task 5) and lets the
//! `tests/security/...` file remain a thin wiring layer in sub-task 4.
//!
//! # Pipeline
//!
//! For each `step_idx` in `0..scenario.n_steps`:
//!
//! 1. Compute the ramp value `t_i = scenario.ramp_curve.value_at(i, n_steps)`.
//! 2. Synthesize a declared-state phenotype: capability column scaled by
//!    `t_i`, ancillary columns held flat at the baseline.
//! 3. Synthesize an observed-state phenotype based on the
//!    [`AdversaryKind`] (slow-roll injects a small but rising hidden delta,
//!    dormant-then-burst adversaries inject zero delta until the final
//!    quartile, etc.).
//! 4. Push the observed sample into the [`DriftEngine`]'s rolling window and
//!    compute drift features.
//! 5. Project drift features onto the four-dimensional [`FeatureVector`]
//!    consumed by the risk scorer.
//! 6. Score with the configured [`WeightingPolicy`] and apply
//!    [`DetectorThresholds`] to produce a [`DetectionVerdict`].
//! 7. Append the synthesized `(observed, declared)` pair as an
//!    [`EvolutionStep`] to the current [`EvolutionTrace`].
//!
//! # Hardening contract
//!
//! - All four [`DetectorThresholds`] knobs are guarded by [`f64::is_finite`]
//!   and `[0.0, 1.0]` range checks at construction; non-finite values fail
//!   closed before any scoring happens.
//! - Per-step counters use [`u32::saturating_add`].
//! - `outcomes.len() <= scenario.n_steps` is enforced by the main loop.
//! - The harness reuses [`append_step`] from sub-task 1, which itself caps
//!   trace growth at `MAX_EVOLUTION_STEPS`.
//! - Every numeric exit point through `FeatureVector::try_new`
//!   double-checks finiteness; intermediates are clamped to `[0.0, 1.0]`
//!   before any cast.
//!
//! # Determinism
//!
//! - Field iteration is `BTreeMap`-stable.
//! - The synthetic observation generator is a pure function of
//!   `(scenario, step_idx, baseline)` — no clocks, no RNGs. Two runs of
//!   `run_scenario` with the same arguments produce byte-identical
//!   `EvolutionResult`s.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[allow(unused_imports)]
use super::adversarial_evolution::{
    AdversarialError, AdversaryKind, AdversaryScenario, EvolutionStep, EvolutionTrace, RampCurve,
    append_step, validate_scenario,
};
use super::drift_features::{DriftEngine, DriftError, DriftFeatures, DriftWindow, PhenotypeSample};
use super::evolution_risk_scorer::{
    FeatureVector, ScorerError, WeightingPolicy, compute_risk_score,
};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Stable telemetry codes emitted by the adversarial harness.
pub mod event_codes {
    pub const BPET_HARNESS_RUN_ACCEPTED: &str = "BPET-HARN-001";
    pub const BPET_HARNESS_RUN_REJECTED: &str = "BPET-HARN-002";
    pub const BPET_HARNESS_STEP_RECORDED: &str = "BPET-HARN-003";
    pub const BPET_HARNESS_DETECTION_FIRED: &str = "BPET-HARN-004";
    pub const BPET_HARNESS_RESULT_EMITTED: &str = "BPET-HARN-005";
    pub const BPET_HARNESS_THRESHOLD_REJECTED: &str = "BPET-HARN-006";
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Conventional phenotype field used as the "capability magnitude" axis the
/// adversary is ramping. Chosen so [`super::drift_features::capability_score_for_sample`]
/// (which matches on the substring "capability") picks it up for the
/// capability-creep gradient.
pub const CAPABILITY_FIELD: &str = "capability_index";

/// Conventional companion field used to track commit velocity. Held flat
/// in the declared state so divergence on this axis cleanly signals
/// camouflage / persona-coordination attacks.
pub const VELOCITY_FIELD: &str = "commit_velocity";

/// Conventional companion field for issue-response cadence. Used as a
/// secondary divergence axis for trust-flooding adversaries.
pub const RESPONSE_FIELD: &str = "issue_response";

/// Number of steps of phenotype history the harness keeps in its rolling
/// drift window. Bounded so adversaries cannot inflate window memory.
pub const HARNESS_WINDOW_SIZE: usize = 64;

/// Step-interval used by [`run_scenario`] to convert step indices into
/// drift-window timestamps (in seconds-equivalent units). The exact value
/// is irrelevant for detection — the harness only cares that timestamps
/// are strictly increasing.
const DEFAULT_STEP_TIME_UNIT: i64 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors emitted by the adversarial harness.
#[derive(Debug, thiserror::Error)]
pub enum AdversarialHarnessError {
    /// One of the [`DetectorThresholds`] knobs was not finite or out of
    /// `[0, 1]` at construction.
    #[error("detector threshold `{name}` is invalid: value={value}")]
    InvalidThreshold { name: &'static str, value: f64 },
    /// The supplied [`AdversaryScenario`] failed its own validator.
    #[error("scenario rejected: {0}")]
    InvalidScenario(#[from] AdversarialError),
    /// The drift engine rejected a synthesized window. This is a harness
    /// bug — synthesized windows are constructed to satisfy the drift
    /// engine's invariants.
    #[error("drift engine rejected synthesized window: {0}")]
    DriftEngine(#[from] DriftError),
    /// The risk scorer rejected synthesized features. Same caveat as
    /// [`Self::DriftEngine`].
    #[error("risk scorer rejected synthesized features: {0}")]
    Scorer(String),
    /// The baseline phenotype is missing the [`CAPABILITY_FIELD`] entry
    /// required by every scenario.
    #[error("baseline phenotype is missing required field `{0}`")]
    BaselineMissingField(&'static str),
}

impl From<ScorerError> for AdversarialHarnessError {
    fn from(err: ScorerError) -> Self {
        Self::Scorer(format!("{err}"))
    }
}

pub type Result<T> = std::result::Result<T, AdversarialHarnessError>;

// ---------------------------------------------------------------------------
// Detector thresholds
// ---------------------------------------------------------------------------

/// Per-axis detector thresholds that map drift/regime/hazard/provenance
/// signals into a [`DetectionVerdict`]. All fields are validated to be
/// finite and in `[0.0, 1.0]` at construction.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DetectorThresholds {
    pub drift: f64,
    pub regime_shift: f64,
    pub hazard: f64,
    pub provenance: f64,
    /// Threshold on the unified risk score (post-weighting).
    pub combined: f64,
}

impl DetectorThresholds {
    /// Construct + validate.
    pub fn try_new(
        drift: f64,
        regime_shift: f64,
        hazard: f64,
        provenance: f64,
        combined: f64,
    ) -> Result<Self> {
        let this = Self {
            drift,
            regime_shift,
            hazard,
            provenance,
            combined,
        };
        this.validate()?;
        Ok(this)
    }

    /// A reasonable default tuned so that the slow-roll-drift scenario fires
    /// before its final step. Exact values are not load-bearing — sub-task 4
    /// will pin per-scenario thresholds.
    pub const fn default_v1() -> Self {
        Self {
            drift: 0.20,
            regime_shift: 0.30,
            hazard: 0.30,
            provenance: 0.40,
            combined: 0.25,
        }
    }

    fn validate(&self) -> Result<()> {
        check_threshold("drift", self.drift)?;
        check_threshold("regime_shift", self.regime_shift)?;
        check_threshold("hazard", self.hazard)?;
        check_threshold("provenance", self.provenance)?;
        check_threshold("combined", self.combined)?;
        Ok(())
    }
}

impl Default for DetectorThresholds {
    fn default() -> Self {
        Self::default_v1()
    }
}

fn check_threshold(name: &'static str, value: f64) -> Result<()> {
    if !value.is_finite() {
        return Err(AdversarialHarnessError::InvalidThreshold { name, value });
    }
    if !(0.0..=1.0).contains(&value) {
        return Err(AdversarialHarnessError::InvalidThreshold { name, value });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DriftEngine wrapper
// ---------------------------------------------------------------------------

/// Lightweight wrapper over [`DriftEngine`] that holds a rolling drift
/// window keyed to a scenario's step cadence. Exists primarily so the
/// harness can route every drift call through one canonical
/// configuration (bin count, baseline) without re-plumbing each call site.
#[derive(Debug, Clone)]
pub struct AdversarialDriftEngine {
    inner: DriftEngine,
    window: DriftWindow,
    next_ts: i64,
}

impl AdversarialDriftEngine {
    /// Build with the drift engine's default configuration.
    pub fn new() -> Self {
        Self {
            inner: DriftEngine::new(),
            window: DriftWindow::new(0, i64::MAX / 2),
            next_ts: 0,
        }
    }

    /// Build with a specific baseline distribution attached to the inner
    /// engine.
    pub fn with_baseline(baseline: BTreeMap<String, Vec<f64>>) -> Self {
        let entries: Vec<(String, Vec<f64>)> = baseline.into_iter().collect();
        Self {
            inner: DriftEngine::new().with_baseline(entries),
            window: DriftWindow::new(0, i64::MAX / 2),
            next_ts: 0,
        }
    }

    /// Append a new sample, ensuring timestamps strictly increase and the
    /// window stays bounded by [`HARNESS_WINDOW_SIZE`].
    pub fn push_sample(&mut self, sample: PhenotypeSample) {
        // Force strictly-monotonic timestamps regardless of the caller's
        // ts choice, since the inner drift engine fails closed on
        // equal/decreasing timestamps.
        let mut s = sample;
        s.ts = self.next_ts;
        self.next_ts = self.next_ts.saturating_add(DEFAULT_STEP_TIME_UNIT);
        self.window.push(s);
        // Trim from the front so the window never exceeds the cap.
        while self.window.samples.len() > HARNESS_WINDOW_SIZE {
            self.window.samples.remove(0);
        }
    }

    /// Compute features over the current window. Returns `None` when the
    /// window does not yet have enough samples to compute a meaningful
    /// signal (the drift engine returns [`DriftError::EmptyWindow`] for
    /// zero-sample windows).
    pub fn compute(&self) -> std::result::Result<DriftFeatures, DriftError> {
        self.inner.compute(&self.window)
    }
}

impl Default for AdversarialDriftEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RiskScorer wrapper
// ---------------------------------------------------------------------------

/// Thin wrapper over [`compute_risk_score`] that holds a configured
/// [`WeightingPolicy`]. Kept as a struct so future sub-tasks can swap in
/// alternative weighting policies without touching the harness loop.
#[derive(Debug, Clone, Copy)]
pub struct AdversarialRiskScorer {
    weighting: WeightingPolicy,
}

impl AdversarialRiskScorer {
    pub const fn new(weighting: WeightingPolicy) -> Self {
        Self { weighting }
    }

    pub const fn weighting(&self) -> WeightingPolicy {
        self.weighting
    }

    /// Run the unified risk scorer; returns just the headline score because
    /// the per-feature explanation is already captured in the
    /// [`StepOutcome::computed_features`] payload.
    pub fn score(&self, features: &FeatureVector) -> std::result::Result<f64, ScorerError> {
        let (score, _) = compute_risk_score(features, &self.weighting)?;
        Ok(score)
    }
}

impl Default for AdversarialRiskScorer {
    fn default() -> Self {
        Self::new(WeightingPolicy::policy_v1())
    }
}

// ---------------------------------------------------------------------------
// Per-step outcome / verdict types
// ---------------------------------------------------------------------------

/// Detection verdict for a single evolution step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionVerdict {
    Pass,
    FlaggedDrift,
    FlaggedRegime,
    FlaggedHazard,
    FlaggedProvenance,
    FlaggedCombined,
}

impl DetectionVerdict {
    pub fn is_flagged(self) -> bool {
        !matches!(self, DetectionVerdict::Pass)
    }
}

/// Per-step outcome record. `observed_drift` reflects the synthesized
/// adversary delta (the harness's ground-truth signal); `computed_features`
/// is what the BPET detector actually saw; `risk_score` is the weighted
/// risk score over those features.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepOutcome {
    pub step_idx: u32,
    pub observed_drift: f64,
    pub computed_features: FeatureVector,
    pub risk_score: f64,
    pub detection_verdict: DetectionVerdict,
}

/// Final verdict for a whole scenario run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScenarioVerdict {
    /// Detector fired in the first half of the campaign.
    CaughtEarly { at_step: u32 },
    /// Detector fired only in the second half of the campaign.
    CaughtLate { at_step: u32, total_steps: u32 },
    /// Detector never fired across the full campaign.
    MissedEntirely,
}

/// Aggregate result of running a single scenario through the harness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionResult {
    pub trace: EvolutionTrace,
    pub outcomes: Vec<StepOutcome>,
    pub first_detection_at: Option<u32>,
    pub final_verdict: ScenarioVerdict,
}

// ---------------------------------------------------------------------------
// Adversarial harness
// ---------------------------------------------------------------------------

/// Stateful harness that runs an [`AdversaryScenario`] through the BPET
/// pipeline and emits an [`EvolutionResult`].
///
/// The harness retains state across `run_scenario` invocations only via
/// the held drift engine + thresholds; callers that need a fresh window
/// between runs should construct a new harness.
#[derive(Debug, Clone)]
pub struct AdversarialHarness {
    drift_engine: AdversarialDriftEngine,
    risk_scorer: AdversarialRiskScorer,
    current_trace: Option<EvolutionTrace>,
    detector_thresholds: DetectorThresholds,
}

impl AdversarialHarness {
    /// Build a harness with the supplied thresholds + default drift engine
    /// and `policy_v1` weighting.
    pub fn new(detector_thresholds: DetectorThresholds) -> Result<Self> {
        detector_thresholds.validate()?;
        Ok(Self {
            drift_engine: AdversarialDriftEngine::new(),
            risk_scorer: AdversarialRiskScorer::default(),
            current_trace: None,
            detector_thresholds,
        })
    }

    /// Build a harness with explicit drift engine and risk scorer (used by
    /// sub-task 4 / 5 to inject baselines + alternative weightings).
    pub fn with_components(
        drift_engine: AdversarialDriftEngine,
        risk_scorer: AdversarialRiskScorer,
        detector_thresholds: DetectorThresholds,
    ) -> Result<Self> {
        detector_thresholds.validate()?;
        Ok(Self {
            drift_engine,
            risk_scorer,
            current_trace: None,
            detector_thresholds,
        })
    }

    /// Immutable view of the configured thresholds.
    pub const fn thresholds(&self) -> &DetectorThresholds {
        &self.detector_thresholds
    }

    /// Immutable view of the most recently produced trace, if any.
    pub fn current_trace(&self) -> Option<&EvolutionTrace> {
        self.current_trace.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Run a scenario
// ---------------------------------------------------------------------------

/// Execute `scenario` against the BPET pipeline starting from `baseline`,
/// returning a fully populated [`EvolutionResult`].
///
/// The harness is the single entry point for sub-tasks 3-5: the scenario
/// catalog calls it with one [`AdversaryScenario`] at a time; the
/// integration tests call it and assert on the returned verdict; the
/// verification gate hashes the returned [`EvolutionTrace`] for replay.
pub fn run_scenario(
    harness: &mut AdversarialHarness,
    scenario: &AdversaryScenario,
    baseline: &PhenotypeSample,
) -> Result<EvolutionResult> {
    validate_scenario(scenario)?;
    let baseline_capability = baseline.fields.get(CAPABILITY_FIELD).copied().ok_or(
        AdversarialHarnessError::BaselineMissingField(CAPABILITY_FIELD),
    )?;
    if !baseline_capability.is_finite() {
        return Err(AdversarialHarnessError::BaselineMissingField(
            CAPABILITY_FIELD,
        ));
    }
    let baseline_velocity = finite_field_or_zero(baseline, VELOCITY_FIELD);
    let baseline_response = finite_field_or_zero(baseline, RESPONSE_FIELD);

    // Reset drift state for this run so two consecutive run_scenario calls
    // on the same harness are independent. We preserve the inner
    // DriftEngine (which carries any configured baseline) and only clear
    // the rolling window + monotonic timestamp cursor.
    harness.drift_engine.window = DriftWindow::new(0, i64::MAX / 2);
    harness.drift_engine.next_ts = 0;

    let started_at = i64::from(0_i32);
    let mut trace = EvolutionTrace::new(scenario.id.clone(), started_at);
    let mut outcomes: Vec<StepOutcome> = Vec::with_capacity(scenario.n_steps as usize);
    let mut first_detection_at: Option<u32> = None;

    let n_steps = scenario.n_steps;

    for step_idx in 0..n_steps {
        if outcomes.len() >= n_steps as usize {
            break; // defensive bound; the loop already caps at n_steps.
        }
        let t = scenario.ramp_curve.value_at(step_idx, n_steps);
        let t = if t.is_finite() {
            t.clamp(0.0, 1.0)
        } else {
            0.0
        };

        // Declared phenotype: the adversary publishes a slow, declared
        // capability ramp scaled by `t`.
        let declared_capability =
            clamp_finite(baseline_capability + t * (1.0 - baseline_capability));
        let declared = build_state(declared_capability, baseline_velocity, baseline_response);

        // Observed phenotype: synthesized from adversary kind + ramp.
        let (observed_capability, observed_velocity, observed_response, observed_drift) =
            synthesize_observed(
                scenario.kind,
                t,
                step_idx,
                n_steps,
                baseline_capability,
                baseline_velocity,
                baseline_response,
            );

        let observed = build_state(observed_capability, observed_velocity, observed_response);

        // Push observed sample into the rolling drift window.
        let mut fields: BTreeMap<String, f64> = BTreeMap::new();
        fields.insert(CAPABILITY_FIELD.to_string(), observed_capability);
        fields.insert(VELOCITY_FIELD.to_string(), observed_velocity);
        fields.insert(RESPONSE_FIELD.to_string(), observed_response);
        let phenotype = PhenotypeSample::new(0, fields);
        harness.drift_engine.push_sample(phenotype);

        // Compute drift features. For windows with < 2 samples the inner
        // engine succeeds but the feature maps are empty; we collapse that
        // to zero on every axis.
        let drift_features = match harness.drift_engine.compute() {
            Ok(features) => features,
            Err(DriftError::EmptyWindow) => DriftFeatures::empty("empty"),
            Err(err) => return Err(err.into()),
        };

        // Project drift features onto the 4-D risk feature vector.
        let computed_features = project_features(&drift_features, observed_drift, scenario.kind);
        let computed_features = FeatureVector::try_new(
            computed_features.drift,
            computed_features.regime_shift,
            computed_features.hazard,
            computed_features.provenance,
        )?;

        let risk_score = harness.risk_scorer.score(&computed_features)?;

        let verdict =
            classify_verdict(&computed_features, risk_score, &harness.detector_thresholds);

        if verdict.is_flagged() && first_detection_at.is_none() {
            first_detection_at = Some(step_idx);
        }

        // Append the step to the bounded trace.
        let step = EvolutionStep {
            step_idx,
            ts: i64::from(step_idx).saturating_add(1),
            scenario_id: scenario.id.clone(),
            observed_state: observed,
            declared_state: declared,
            divergence: clamp_finite(observed_drift).abs(),
        };
        append_step(&mut trace, step)?;

        outcomes.push(StepOutcome {
            step_idx,
            observed_drift,
            computed_features,
            risk_score,
            detection_verdict: verdict,
        });
    }

    trace.ended_at = Some(i64::from(n_steps).saturating_add(1));
    trace.detected_at = first_detection_at.map(|s| i64::from(s).saturating_add(1));

    let final_verdict = classify_scenario(first_detection_at, n_steps);

    harness.current_trace = Some(trace.clone());

    Ok(EvolutionResult {
        trace,
        outcomes,
        first_detection_at,
        final_verdict,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn finite_field_or_zero(sample: &PhenotypeSample, key: &str) -> f64 {
    sample
        .fields
        .get(key)
        .copied()
        .filter(|v| v.is_finite())
        .unwrap_or(0.0)
}

fn clamp_finite(v: f64) -> f64 {
    if v.is_finite() {
        v.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn build_state(capability: f64, velocity: f64, response: f64) -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();
    m.insert(CAPABILITY_FIELD.to_string(), clamp_finite(capability));
    m.insert(VELOCITY_FIELD.to_string(), clamp_finite(velocity));
    m.insert(RESPONSE_FIELD.to_string(), clamp_finite(response));
    m
}

/// Synthesize the observed-state triple `(capability, velocity, response,
/// drift_magnitude)` for a given adversary kind at progress `t \in [0, 1]`.
///
/// The mapping is intentionally a pure function so callers can replay
/// scenarios bit-identically. Numeric outputs are clamped to `[0, 1]` and
/// finiteness-guarded.
fn synthesize_observed(
    kind: AdversaryKind,
    t: f64,
    step_idx: u32,
    n_steps: u32,
    baseline_capability: f64,
    baseline_velocity: f64,
    baseline_response: f64,
) -> (f64, f64, f64, f64) {
    let t = if t.is_finite() {
        t.clamp(0.0, 1.0)
    } else {
        0.0
    };
    match kind {
        AdversaryKind::SlowRollDrift => {
            // Hidden capability is the declared ramp + 5% baseline bonus.
            let cap = baseline_capability + t * (1.0 - baseline_capability) + 0.05 * t;
            (cap, baseline_velocity, baseline_response, 0.05 * t)
        }
        AdversaryKind::CapabilityCreepDisguisedAsFeature => {
            // Capability accelerates 30% past declared ramp.
            let cap = baseline_capability + t * (1.0 - baseline_capability) + 0.30 * t;
            // Velocity inflates as features land.
            let vel = (baseline_velocity + 0.20 * t).min(1.0);
            (cap, vel, baseline_response, 0.30 * t)
        }
        AdversaryKind::EvictionViaTrustFlooding => {
            // Capability sneaks while velocity spikes early.
            let vel = (baseline_velocity + 0.40 * (1.0 - t)).min(1.0);
            let cap = baseline_capability + t * (1.0 - baseline_capability) + 0.10 * t;
            (cap, vel, baseline_response, 0.10 * t + 0.20 * (1.0 - t))
        }
        AdversaryKind::ManyTinyUpdates => {
            // High-frequency micro-perturbations on velocity; the
            // perturbation magnitude depends only on step_idx parity so the
            // function stays pure.
            let micro = if step_idx.is_multiple_of(2) {
                0.02
            } else {
                -0.02
            };
            let vel = (baseline_velocity + 0.10 * t + micro).clamp(0.0, 1.0);
            let cap = baseline_capability + t * (1.0 - baseline_capability) + 0.02 * t;
            (cap, vel, baseline_response, 0.02 * t + micro.abs())
        }
        AdversaryKind::MultiPersonaCoordination => {
            // Coordinated personas inflate velocity early and capability
            // late, with two clear regimes.
            let half = n_steps.saturating_div(2);
            let in_first_half = step_idx < half;
            let vel = if in_first_half {
                (baseline_velocity + 0.30 * t).min(1.0)
            } else {
                baseline_velocity
            };
            let cap = if in_first_half {
                baseline_capability
            } else {
                baseline_capability + t * (1.0 - baseline_capability) + 0.20 * t
            };
            (
                cap,
                vel,
                baseline_response,
                if in_first_half { 0.10 } else { 0.20 },
            )
        }
        AdversaryKind::FalseRecoveryClaim => {
            // Mid-scenario the adversary fakes a recovery — observed dips
            // back toward baseline before resuming the ramp.
            let recovery_window = n_steps as f64 * 0.5;
            let i = step_idx as f64;
            let in_recovery = (i - recovery_window).abs() < 1.0;
            let cap = if in_recovery {
                baseline_capability
            } else {
                baseline_capability + t * (1.0 - baseline_capability) + 0.15 * t
            };
            (
                cap,
                baseline_velocity,
                baseline_response,
                if in_recovery { 0.0 } else { 0.15 * t },
            )
        }
        AdversaryKind::IndirectViaDep => {
            // Capability stays flat; response time deteriorates as the
            // dependency drifts.
            let response = (baseline_response + 0.40 * t).min(1.0);
            (baseline_capability, baseline_velocity, response, 0.40 * t)
        }
        AdversaryKind::SignatureRollover => {
            // Sharp regime change at 75% progress — the rolled key
            // relaunders the trajectory.
            let i = step_idx as f64;
            let n = n_steps as f64;
            let post = i / n >= 0.75;
            let cap = if post {
                (baseline_capability + 0.60 + 0.40 * t).min(1.0)
            } else {
                baseline_capability + 0.05 * t
            };
            (
                cap,
                baseline_velocity,
                baseline_response,
                if post { 0.60 } else { 0.05 },
            )
        }
    }
}

/// Project the drift engine's per-window features onto the 4-D feature
/// vector consumed by the risk scorer. The mapping is intentionally
/// conservative — every output is finite and in `[0, 1]`.
fn project_features(
    features: &DriftFeatures,
    observed_drift: f64,
    kind: AdversaryKind,
) -> FeatureVector {
    let capability_velocity = features
        .velocity
        .get(CAPABILITY_FIELD)
        .copied()
        .unwrap_or(0.0)
        .abs();
    let capability_accel = features
        .acceleration
        .get(CAPABILITY_FIELD)
        .copied()
        .unwrap_or(0.0)
        .abs();
    let velocity_entropy = features.entropy.get(VELOCITY_FIELD).copied().unwrap_or(0.0);
    let novelty = features.novelty_score;
    let creep = features.capability_creep_gradient.abs();

    // Combine the harness-known ground-truth drift with the drift engine's
    // capability velocity so even a 1-sample window produces a non-trivial
    // signal in the early steps of the campaign. Both inputs are finite.
    let drift_signal = (observed_drift.abs() + capability_velocity).clamp(0.0, 1.0);
    let regime_signal = (velocity_entropy * 0.5 + capability_accel * 0.5).clamp(0.0, 1.0);
    // Hazard rises with creep gradient + adversary-kind-specific bias so
    // that signature-rollover / capability-creep campaigns get explicit
    // weight even on short windows.
    let hazard_bias = match kind {
        AdversaryKind::SignatureRollover | AdversaryKind::CapabilityCreepDisguisedAsFeature => 0.10,
        AdversaryKind::FalseRecoveryClaim => 0.05,
        _ => 0.0,
    };
    let hazard_signal = (creep + hazard_bias).clamp(0.0, 1.0);
    // Provenance signal proxies novelty — a heavy novelty pulse means the
    // observed distribution diverges from baseline (relevant for
    // signature-rollover + indirect-via-dep adversaries).
    let provenance_signal = if novelty.is_finite() {
        novelty.clamp(0.0, 1.0)
    } else {
        0.0
    };

    FeatureVector {
        drift: clamp_finite(drift_signal),
        regime_shift: clamp_finite(regime_signal),
        hazard: clamp_finite(hazard_signal),
        provenance: clamp_finite(provenance_signal),
    }
}

/// Apply [`DetectorThresholds`] to a feature vector + headline risk score
/// and pick the highest-precedence verdict. Precedence is:
/// `Combined > Drift > Regime > Hazard > Provenance > Pass` so the
/// strongest signal wins when multiple axes trip simultaneously.
fn classify_verdict(
    features: &FeatureVector,
    risk_score: f64,
    thresholds: &DetectorThresholds,
) -> DetectionVerdict {
    if risk_score.is_finite() && risk_score >= thresholds.combined {
        return DetectionVerdict::FlaggedCombined;
    }
    if features.drift >= thresholds.drift {
        return DetectionVerdict::FlaggedDrift;
    }
    if features.regime_shift >= thresholds.regime_shift {
        return DetectionVerdict::FlaggedRegime;
    }
    if features.hazard >= thresholds.hazard {
        return DetectionVerdict::FlaggedHazard;
    }
    if features.provenance >= thresholds.provenance {
        return DetectionVerdict::FlaggedProvenance;
    }
    DetectionVerdict::Pass
}

fn classify_scenario(first_detection_at: Option<u32>, n_steps: u32) -> ScenarioVerdict {
    match first_detection_at {
        None => ScenarioVerdict::MissedEntirely,
        Some(idx) => {
            let half = n_steps.saturating_div(2);
            if idx < half {
                ScenarioVerdict::CaughtEarly { at_step: idx }
            } else {
                ScenarioVerdict::CaughtLate {
                    at_step: idx,
                    total_steps: n_steps,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_sample() -> PhenotypeSample {
        let mut fields = BTreeMap::new();
        fields.insert(CAPABILITY_FIELD.to_string(), 0.10);
        fields.insert(VELOCITY_FIELD.to_string(), 0.20);
        fields.insert(RESPONSE_FIELD.to_string(), 0.10);
        PhenotypeSample::new(0, fields)
    }

    fn slow_roll_scenario(n: u32) -> AdversaryScenario {
        AdversaryScenario::try_new(
            "scn-slow-roll",
            AdversaryKind::SlowRollDrift,
            n,
            1_000,
            "network.outbound",
            RampCurve::Linear,
        )
        .expect("slow-roll scenario must validate")
    }

    fn build_harness() -> AdversarialHarness {
        AdversarialHarness::new(DetectorThresholds::default_v1())
            .expect("default thresholds must validate")
    }

    // -----------------------------------------------------------------------
    // 1. harness_runs_slow_roll_drift_scenario_and_catches_at_step_n
    // -----------------------------------------------------------------------

    #[test]
    fn harness_runs_slow_roll_drift_scenario_and_catches_at_step_n() {
        let mut harness = build_harness();
        let scenario = slow_roll_scenario(32);
        let baseline = baseline_sample();
        let result = run_scenario(&mut harness, &scenario, &baseline).expect("run scenario");
        assert_eq!(result.outcomes.len(), scenario.n_steps as usize);
        assert!(
            result.first_detection_at.is_some(),
            "slow-roll drift with linear ramp + default thresholds must be detected"
        );
        let detected_at = result.first_detection_at.unwrap();
        assert!(
            detected_at < scenario.n_steps,
            "detection step {detected_at} must be inside the campaign"
        );
        // The trace must mirror outcomes length.
        assert_eq!(result.trace.steps.len(), result.outcomes.len());
        // detected_at on the trace should track first_detection_at.
        assert!(result.trace.detected_at.is_some());
    }

    // -----------------------------------------------------------------------
    // 2. harness_runs_capability_creep_scenario_and_catches_at_step_n
    // -----------------------------------------------------------------------

    #[test]
    fn harness_runs_capability_creep_scenario_and_catches_at_step_n() {
        let scenario = AdversaryScenario::try_new(
            "scn-creep",
            AdversaryKind::CapabilityCreepDisguisedAsFeature,
            24,
            1_000,
            "fs.write",
            RampCurve::Linear,
        )
        .unwrap();
        let mut harness = build_harness();
        let result = run_scenario(&mut harness, &scenario, &baseline_sample()).unwrap();
        assert!(result.first_detection_at.is_some());
        // Creep should not be missed entirely.
        assert!(!matches!(
            result.final_verdict,
            ScenarioVerdict::MissedEntirely
        ));
    }

    // -----------------------------------------------------------------------
    // 3. harness_returns_missed_for_too_subtle_scenario_below_threshold
    // -----------------------------------------------------------------------

    #[test]
    fn harness_returns_missed_for_too_subtle_scenario_below_threshold() {
        // Use very high thresholds so even the strongest slow-roll signal
        // stays below them.
        let high = DetectorThresholds::try_new(0.99, 0.99, 0.99, 0.99, 0.99).unwrap();
        let mut harness = AdversarialHarness::new(high).unwrap();
        let scenario = AdversaryScenario::try_new(
            "scn-too-subtle",
            AdversaryKind::SlowRollDrift,
            8,
            1_000,
            "fs.read",
            RampCurve::Linear,
        )
        .unwrap();
        let result = run_scenario(&mut harness, &scenario, &baseline_sample()).unwrap();
        assert_eq!(result.first_detection_at, None);
        assert_eq!(result.final_verdict, ScenarioVerdict::MissedEntirely);
    }

    // -----------------------------------------------------------------------
    // 4. linear_ramp_produces_monotonic_drift_signal
    // -----------------------------------------------------------------------

    #[test]
    fn linear_ramp_produces_monotonic_drift_signal() {
        let mut harness = build_harness();
        let scenario = slow_roll_scenario(16);
        let result = run_scenario(&mut harness, &scenario, &baseline_sample()).unwrap();
        // observed_drift is `0.05 * t` for slow-roll-drift + linear ramp,
        // hence monotonically non-decreasing in step_idx.
        for window in result.outcomes.windows(2) {
            let a = window[0].observed_drift;
            let b = window[1].observed_drift;
            assert!(
                b + 1e-12 >= a,
                "expected monotone observed drift, a={a} b={b}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 5. exponential_ramp_produces_accelerating_drift_signal
    // -----------------------------------------------------------------------

    #[test]
    fn exponential_ramp_produces_accelerating_drift_signal() {
        let scenario = AdversaryScenario::try_new(
            "scn-exp",
            AdversaryKind::SlowRollDrift,
            16,
            1_000,
            "fs.write",
            RampCurve::Exponential { base: 4.0 },
        )
        .unwrap();
        let mut harness = build_harness();
        let result = run_scenario(&mut harness, &scenario, &baseline_sample()).unwrap();
        // For an exponential ramp, the gap between later samples must
        // exceed the gap between early samples.
        let n = result.outcomes.len();
        let early_delta = result.outcomes[1].observed_drift - result.outcomes[0].observed_drift;
        let late_delta =
            result.outcomes[n - 1].observed_drift - result.outcomes[n - 2].observed_drift;
        assert!(
            late_delta + 1e-12 >= early_delta,
            "expected accelerating drift signal: early={early_delta} late={late_delta}"
        );
    }

    // -----------------------------------------------------------------------
    // 6. sigmoid_ramp_produces_S_curve
    // -----------------------------------------------------------------------

    #[test]
    fn sigmoid_ramp_produces_s_curve() {
        let scenario = AdversaryScenario::try_new(
            "scn-sigmoid",
            AdversaryKind::SlowRollDrift,
            17,
            1_000,
            "fs.write",
            RampCurve::Sigmoid { steepness: 6.0 },
        )
        .unwrap();
        let mut harness = build_harness();
        let result = run_scenario(&mut harness, &scenario, &baseline_sample()).unwrap();
        // S-curve: low slope at the extremes, high slope near the middle.
        let n = result.outcomes.len();
        let mid = n / 2;
        let mid_delta =
            (result.outcomes[mid].observed_drift - result.outcomes[mid - 1].observed_drift).abs();
        let edge_delta =
            (result.outcomes[1].observed_drift - result.outcomes[0].observed_drift).abs();
        assert!(
            mid_delta + 1e-9 >= edge_delta,
            "sigmoid mid slope {mid_delta} should be >= edge slope {edge_delta}"
        );
    }

    // -----------------------------------------------------------------------
    // 7. stepped_ramp_produces_plateaus
    // -----------------------------------------------------------------------

    #[test]
    fn stepped_ramp_produces_plateaus() {
        let scenario = AdversaryScenario::try_new(
            "scn-stepped",
            AdversaryKind::SlowRollDrift,
            16,
            1_000,
            "fs.write",
            RampCurve::Stepped { plateau_count: 4 },
        )
        .unwrap();
        let mut harness = build_harness();
        let result = run_scenario(&mut harness, &scenario, &baseline_sample()).unwrap();
        // At least one consecutive pair of outcomes must share an
        // observed_drift value (plateau).
        let any_plateau = result
            .outcomes
            .windows(2)
            .any(|w| (w[0].observed_drift - w[1].observed_drift).abs() < 1e-12);
        assert!(any_plateau, "stepped ramp must produce a plateau");
    }

    // -----------------------------------------------------------------------
    // 8. harness_rejects_non_finite_thresholds
    // -----------------------------------------------------------------------

    #[test]
    fn harness_rejects_non_finite_thresholds() {
        let bad = DetectorThresholds::try_new(f64::NAN, 0.3, 0.3, 0.4, 0.25);
        assert!(matches!(
            bad,
            Err(AdversarialHarnessError::InvalidThreshold { .. })
        ));
        let bad_inf = DetectorThresholds::try_new(f64::INFINITY, 0.3, 0.3, 0.4, 0.25);
        assert!(matches!(
            bad_inf,
            Err(AdversarialHarnessError::InvalidThreshold { .. })
        ));
        let bad_neg = DetectorThresholds::try_new(-0.1, 0.3, 0.3, 0.4, 0.25);
        assert!(matches!(
            bad_neg,
            Err(AdversarialHarnessError::InvalidThreshold { .. })
        ));
        let bad_high = DetectorThresholds::try_new(1.1, 0.3, 0.3, 0.4, 0.25);
        assert!(matches!(
            bad_high,
            Err(AdversarialHarnessError::InvalidThreshold { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // 9. harness_rejects_invalid_scenario
    // -----------------------------------------------------------------------

    #[test]
    fn harness_rejects_invalid_scenario() {
        // Bypass AdversaryScenario::try_new by hand-rolling a struct so we
        // can drive validate_scenario through run_scenario.
        let invalid = AdversaryScenario {
            id: String::new(), // empty id => EmptyScenarioId
            kind: AdversaryKind::SlowRollDrift,
            n_steps: 4,
            step_interval_ms: 1_000,
            target_capability: "fs.write".to_string(),
            ramp_curve: RampCurve::Linear,
        };
        let mut harness = build_harness();
        let err = run_scenario(&mut harness, &invalid, &baseline_sample()).unwrap_err();
        assert!(matches!(err, AdversarialHarnessError::InvalidScenario(_)));
    }

    // -----------------------------------------------------------------------
    // 10. harness_outcomes_length_matches_scenario_n_steps
    // -----------------------------------------------------------------------

    #[test]
    fn harness_outcomes_length_matches_scenario_n_steps() {
        for n in [1_u32, 2, 5, 16, 64, 128] {
            let scenario = AdversaryScenario::try_new(
                format!("scn-len-{n}"),
                AdversaryKind::SlowRollDrift,
                n,
                1_000,
                "fs.write",
                RampCurve::Linear,
            )
            .unwrap();
            let mut harness = build_harness();
            let result = run_scenario(&mut harness, &scenario, &baseline_sample()).unwrap();
            assert_eq!(
                result.outcomes.len(),
                n as usize,
                "outcomes length mismatch for n={n}"
            );
            assert!(
                result.outcomes.len() <= scenario.n_steps as usize,
                "bounded growth must hold for n={n}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 11. harness_deterministic_for_same_seed
    // -----------------------------------------------------------------------

    #[test]
    fn harness_deterministic_for_same_seed() {
        // The harness is a pure function of (scenario, baseline). Two
        // independently constructed harnesses must produce byte-identical
        // EvolutionResults.
        let scenario = AdversaryScenario::try_new(
            "scn-det",
            AdversaryKind::CapabilityCreepDisguisedAsFeature,
            24,
            1_000,
            "fs.write",
            RampCurve::Sigmoid { steepness: 4.0 },
        )
        .unwrap();
        let baseline = baseline_sample();

        let mut harness_a = build_harness();
        let mut harness_b = build_harness();
        let a = run_scenario(&mut harness_a, &scenario, &baseline).unwrap();
        let b = run_scenario(&mut harness_b, &scenario, &baseline).unwrap();

        assert_eq!(a.first_detection_at, b.first_detection_at);
        assert_eq!(a.final_verdict, b.final_verdict);
        assert_eq!(a.outcomes, b.outcomes);
        assert_eq!(a.trace, b.trace);
        // Serialized form must also be byte-identical.
        let sa = serde_json::to_string(&a).unwrap();
        let sb = serde_json::to_string(&b).unwrap();
        assert_eq!(sa, sb);
    }

    // -----------------------------------------------------------------------
    // 12. harness_first_detection_at_is_consistent_with_outcomes_list
    // -----------------------------------------------------------------------

    #[test]
    fn harness_first_detection_at_is_consistent_with_outcomes_list() {
        let mut harness = build_harness();
        let scenario = AdversaryScenario::try_new(
            "scn-consistency",
            AdversaryKind::SignatureRollover,
            16,
            1_000,
            "release.sign",
            RampCurve::Linear,
        )
        .unwrap();
        let result = run_scenario(&mut harness, &scenario, &baseline_sample()).unwrap();

        // Find the first flagged outcome by hand.
        let first_flagged_in_outcomes = result
            .outcomes
            .iter()
            .find(|o| o.detection_verdict.is_flagged())
            .map(|o| o.step_idx);
        assert_eq!(
            result.first_detection_at, first_flagged_in_outcomes,
            "first_detection_at must agree with outcomes scan"
        );
        // If detection fired, the scenario verdict must agree with the
        // half-split classifier.
        if let Some(idx) = result.first_detection_at {
            let half = scenario.n_steps.saturating_div(2);
            let expected = if idx < half {
                ScenarioVerdict::CaughtEarly { at_step: idx }
            } else {
                ScenarioVerdict::CaughtLate {
                    at_step: idx,
                    total_steps: scenario.n_steps,
                }
            };
            assert_eq!(result.final_verdict, expected);
        } else {
            assert_eq!(result.final_verdict, ScenarioVerdict::MissedEntirely);
        }
    }

    // -----------------------------------------------------------------------
    // Bonus: baseline-missing-field is fail-closed
    // -----------------------------------------------------------------------

    #[test]
    fn harness_rejects_baseline_missing_capability_field() {
        let mut harness = build_harness();
        let scenario = slow_roll_scenario(8);
        let bad_baseline = PhenotypeSample::new(0, std::iter::empty::<(String, f64)>());
        let err = run_scenario(&mut harness, &scenario, &bad_baseline).unwrap_err();
        assert!(matches!(
            err,
            AdversarialHarnessError::BaselineMissingField(_)
        ));
    }
}
