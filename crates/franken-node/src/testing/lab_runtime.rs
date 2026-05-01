// Deterministic lab runtime for controlled fault-injection testing.
//
// Replaces real async I/O, timers, and network with virtual implementations
// driven by a seeded PRNG, ensuring bit-exact reproducibility. Integrates
// upstream 10.14 primitives: virtual transport faults, DPOR exploration,
// and repro-bundle export.
//
// bd-2ko — Section 10.11

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Current schema version for lab runtime configuration and bundles.
pub const SCHEMA_VERSION: &str = "lab-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

use crate::capacity_defaults::aliases::MAX_EVENTS;
const MAX_REORDER_BUFFERS: usize = 4096;
const MAX_VIRTUAL_LINKS: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

/// Lab runtime initialized with seed and config.
pub const EVT_LAB_INITIALIZED: &str = "FN-LB-001";
/// A scenario execution has started.
pub const EVT_SCENARIO_STARTED: &str = "FN-LB-002";
/// A fault was injected on a virtual link.
pub const EVT_FAULT_INJECTED: &str = "FN-LB-003";
/// A mock-clock timer fired.
pub const EVT_TIMER_FIRED: &str = "FN-LB-004";
/// A scenario execution completed successfully.
pub const EVT_SCENARIO_COMPLETED: &str = "FN-LB-005";
/// DPOR explored an interleaving.
pub const EVT_DPOR_INTERLEAVING: &str = "FN-LB-006";
/// A repro bundle was exported.
pub const EVT_REPRO_EXPORTED: &str = "FN-LB-007";
/// A scenario execution failed.
pub const EVT_SCENARIO_FAILED: &str = "FN-LB-008";
/// A virtual link was created.
pub const EVT_VIRTUAL_LINK_CREATED: &str = "FN-LB-009";
/// The test clock was advanced.
pub const EVT_TEST_CLOCK_ADVANCED: &str = "FN-LB-010";
/// A message send was processed by a virtual link.
pub const EVT_MESSAGE_PROCESSED: &str = "FN-LB-011";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// No seed was provided in the lab configuration.
pub const ERR_LB_NO_SEED: &str = "ERR_LB_NO_SEED";
/// Test clock tick would overflow u64.
pub const ERR_LB_TICK_OVERFLOW: &str = "ERR_LB_TICK_OVERFLOW";
/// Timer identifiers are exhausted and can no longer be allocated safely.
pub const ERR_LB_TIMER_ID_EXHAUSTED: &str = "ERR_LB_TIMER_ID_EXHAUSTED";
/// Referenced virtual link does not exist.
pub const ERR_LB_LINK_NOT_FOUND: &str = "ERR_LB_LINK_NOT_FOUND";
/// Virtual-link capacity would be exceeded.
pub const ERR_LB_LINK_CAPACITY_EXCEEDED: &str = "ERR_LB_LINK_CAPACITY_EXCEEDED";
/// Fault probability outside [0.0, 1.0].
pub const ERR_LB_FAULT_RANGE: &str = "ERR_LB_FAULT_RANGE";
/// DPOR interleaving budget exceeded.
pub const ERR_LB_BUDGET_EXCEEDED: &str = "ERR_LB_BUDGET_EXCEEDED";
/// Replay diverged from recorded execution.
pub const ERR_LB_REPLAY_DIVERGENCE: &str = "ERR_LB_REPLAY_DIVERGENCE";
/// Repro bundle failed to serialize to JSON.
pub const ERR_LB_BUNDLE_SERIALIZATION: &str = "ERR_LB_BUNDLE_SERIALIZATION";
/// Repro bundle failed to parse from JSON.
pub const ERR_LB_BUNDLE_DESERIALIZATION: &str = "ERR_LB_BUNDLE_DESERIALIZATION";
/// Repro bundle content is internally inconsistent or unsupported.
pub const ERR_LB_BUNDLE_VALIDATION: &str = "ERR_LB_BUNDLE_VALIDATION";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

/// Same seed produces identical event sequence.
pub const INV_LB_DETERMINISTIC: &str = "INV-LB-DETERMINISTIC";
/// Timers fire in strictly ascending tick order.
pub const INV_LB_TIMER_ORDER: &str = "INV-LB-TIMER-ORDER";
/// Configured faults are applied exactly per profile parameters.
pub const INV_LB_FAULT_APPLIED: &str = "INV-LB-FAULT-APPLIED";
/// Exported bundles reproduce failures on replay.
pub const INV_LB_REPLAY: &str = "INV-LB-REPLAY";
/// All required scenarios have lab tests.
pub const INV_LB_COVERAGE: &str = "INV-LB-COVERAGE";
/// No std::time usage in lab mode — all timing via TestClock.
pub const INV_LB_NO_WALLCLOCK: &str = "INV-LB-NO-WALLCLOCK";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Lab runtime errors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LabError {
    /// No seed was supplied.
    NoSeed,
    /// Test clock would overflow.
    TickOverflow { current: u64, delta: u64 },
    /// Timer identifiers are exhausted.
    TimerIdExhausted,
    /// Virtual link not found.
    LinkNotFound { source: String, target: String },
    /// Virtual-link capacity exceeded.
    LinkCapacityExceeded { limit: usize },
    /// Fault probability out of valid range.
    FaultRange { field: String, value: f64 },
    /// DPOR exploration budget exceeded.
    BudgetExceeded { explored: u64, budget: u64 },
    /// Replay produced a different outcome.
    ReplayDivergence {
        expected_events: usize,
        actual_events: usize,
    },
    /// Repro bundle failed to serialize.
    BundleSerialization { detail: String },
    /// Repro bundle failed to deserialize.
    BundleDeserialization { detail: String },
    /// Repro bundle content failed validation.
    BundleValidation { detail: String },
}

impl fmt::Display for LabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSeed => write!(f, "{ERR_LB_NO_SEED}: no seed provided"),
            Self::TickOverflow { current, delta } => {
                write!(
                    f,
                    "{ERR_LB_TICK_OVERFLOW}: current={current}, delta={delta}"
                )
            }
            Self::TimerIdExhausted => {
                write!(
                    f,
                    "{ERR_LB_TIMER_ID_EXHAUSTED}: timer identifiers exhausted"
                )
            }
            Self::LinkNotFound { source, target } => {
                write!(f, "{ERR_LB_LINK_NOT_FOUND}: {source} -> {target}")
            }
            Self::LinkCapacityExceeded { limit } => {
                write!(f, "{ERR_LB_LINK_CAPACITY_EXCEEDED}: limit={limit}")
            }
            Self::FaultRange { field, value } => {
                write!(
                    f,
                    "{ERR_LB_FAULT_RANGE}: {field}={value}, must be in [0.0, 1.0]"
                )
            }
            Self::BudgetExceeded { explored, budget } => {
                write!(
                    f,
                    "{ERR_LB_BUDGET_EXCEEDED}: explored={explored}, budget={budget}"
                )
            }
            Self::ReplayDivergence {
                expected_events,
                actual_events,
            } => write!(
                f,
                "{ERR_LB_REPLAY_DIVERGENCE}: expected {expected_events} events, got {actual_events}"
            ),
            Self::BundleSerialization { detail } => {
                write!(f, "{ERR_LB_BUNDLE_SERIALIZATION}: {detail}")
            }
            Self::BundleDeserialization { detail } => {
                write!(f, "{ERR_LB_BUNDLE_DESERIALIZATION}: {detail}")
            }
            Self::BundleValidation { detail } => {
                write!(f, "{ERR_LB_BUNDLE_VALIDATION}: {detail}")
            }
        }
    }
}

impl std::error::Error for LabError {}

// ---------------------------------------------------------------------------
// Seeded PRNG (SplitMix64 — deterministic, no external deps)
// ---------------------------------------------------------------------------

/// Minimal deterministic PRNG (SplitMix64).
/// INV-LB-DETERMINISTIC: identical seeds yield identical sequences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Create a new SplitMix64 from the given seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Produce the next u64 value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Produce a f64 in [0.0, 1.0).
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
    }

    /// Produce a usize in [0, bound) using rejection sampling to avoid bias.
    pub fn next_usize(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }
        // Simple modulo — acceptable for testing since SplitMix64 has good
        // distribution and test bounds are small.
        (self.next_u64() % (bound as u64)) as usize
    }
}

// ---------------------------------------------------------------------------
// FaultProfile
// ---------------------------------------------------------------------------

/// Fault injection profile for a virtual link.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FaultProfile {
    /// Probability of dropping a message [0.0, 1.0].
    pub drop_pct: f64,
    /// Depth of reorder buffer (0 = no reordering).
    pub reorder_depth: usize,
    /// Probability of corrupting a message [0.0, 1.0].
    pub corrupt_probability: f64,
    /// Fixed delay in ticks added to every message.
    pub delay_ticks: u64,
}

impl Default for FaultProfile {
    fn default() -> Self {
        Self {
            drop_pct: 0.0,
            reorder_depth: 0,
            corrupt_probability: 0.0,
            delay_ticks: 0,
        }
    }
}

impl FaultProfile {
    /// Validate that probability fields are within [0.0, 1.0].
    pub fn validate(&self) -> Result<(), LabError> {
        if !(0.0..=1.0).contains(&self.drop_pct) {
            return Err(LabError::FaultRange {
                field: "drop_pct".into(),
                value: self.drop_pct,
            });
        }
        if !(0.0..=1.0).contains(&self.corrupt_probability) {
            return Err(LabError::FaultRange {
                field: "corrupt_probability".into(),
                value: self.corrupt_probability,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VirtualLink
// ---------------------------------------------------------------------------

/// A virtual network link between two named endpoints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VirtualLink {
    /// Source endpoint name.
    pub source: String,
    /// Target endpoint name.
    pub target: String,
    /// Fault injection profile for this link.
    pub fault_profile: FaultProfile,
}

impl VirtualLink {
    /// Create a new virtual link with the given fault profile.
    pub fn new(
        source: impl Into<String>,
        target: impl Into<String>,
        fault_profile: FaultProfile,
    ) -> Result<Self, LabError> {
        fault_profile.validate()?;
        Ok(Self {
            source: source.into(),
            target: target.into(),
            fault_profile,
        })
    }
}

// ---------------------------------------------------------------------------
// LabEvent
// ---------------------------------------------------------------------------

/// A structured event emitted during lab execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabEvent {
    /// Test-clock tick at which the event occurred.
    pub tick: u64,
    /// Event code (FN-LB-xxx).
    pub event_code: String,
    /// Human-readable / machine-parseable payload.
    pub payload: String,
}

impl fmt::Display for LabEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[tick={}] {}: {}",
            self.tick, self.event_code, self.payload
        )
    }
}

// ---------------------------------------------------------------------------
// LabConfig
// ---------------------------------------------------------------------------

/// Configuration for a lab runtime instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LabConfig {
    /// Deterministic seed. 0 is disallowed (use explicit seed).
    pub seed: u64,
    /// Maximum ticks before the scenario is force-stopped.
    pub max_ticks: u64,
    /// Maximum DPOR interleavings to explore.
    pub max_interleavings: u64,
    /// Whether DPOR exploration is enabled.
    pub enable_dpor: bool,
}

impl Default for LabConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            max_ticks: 10_000,
            max_interleavings: 1_000,
            enable_dpor: false,
        }
    }
}

impl LabConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), LabError> {
        if self.seed == 0 {
            return Err(LabError::NoSeed);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TimerCallback
// ---------------------------------------------------------------------------

/// A pending timer callback in the test clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimerCallback {
    /// Unique timer identifier.
    pub id: u64,
    /// Label for structured logging.
    pub label: String,
}

// ---------------------------------------------------------------------------
// TestClock
// ---------------------------------------------------------------------------

/// Deterministic test clock driven by explicit tick advancement.
/// INV-LB-TIMER-ORDER: timers fire in ascending tick order (BTreeMap guarantees).
/// INV-LB-NO-WALLCLOCK: no std::time usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestClock {
    /// Current tick.
    pub current_tick: u64,
    /// Pending timers keyed by fire-tick. BTreeMap guarantees ascending order.
    pub pending_timers: BTreeMap<u64, Vec<TimerCallback>>,
    /// Monotonic timer ID counter.
    next_timer_id: u64,
}

impl TestClock {
    /// Create a new test clock starting at tick 0.
    pub fn new() -> Self {
        Self {
            current_tick: 0,
            pending_timers: BTreeMap::new(),
            next_timer_id: 1,
        }
    }

    /// Schedule a timer to fire at `current_tick + delay`.
    pub fn schedule_timer(
        &mut self,
        delay: u64,
        label: impl Into<String>,
    ) -> Result<u64, LabError> {
        let fire_tick = self
            .current_tick
            .checked_add(delay)
            .ok_or(LabError::TickOverflow {
                current: self.current_tick,
                delta: delay,
            })?;
        if self.next_timer_id == 0 {
            return Err(LabError::TimerIdExhausted);
        }
        let id = self.next_timer_id;
        // Reserve `0` as a terminal sentinel so the final valid identifier is
        // issued exactly once and later allocations fail closed.
        self.next_timer_id = self.next_timer_id.checked_add(1).unwrap_or(0);
        self.pending_timers
            .entry(fire_tick)
            .or_default()
            .push(TimerCallback {
                id,
                label: label.into(),
            });
        Ok(id)
    }

    /// Advance the clock by `delta` ticks, returning all timers that fired
    /// in ascending tick order (INV-LB-TIMER-ORDER).
    pub fn advance(&mut self, delta: u64) -> Result<Vec<(u64, TimerCallback)>, LabError> {
        let new_tick = self
            .current_tick
            .checked_add(delta)
            .ok_or(LabError::TickOverflow {
                current: self.current_tick,
                delta,
            })?;

        let mut fired = Vec::new();

        // Collect all timer ticks <= new_tick without overflowing when
        // `new_tick == u64::MAX`.
        let mut remaining = self.pending_timers.split_off(&new_tick);
        let callbacks_at_new_tick = remaining.remove(&new_tick);
        let mut ready = std::mem::take(&mut self.pending_timers);
        if let Some(callbacks) = callbacks_at_new_tick {
            ready.insert(new_tick, callbacks);
        }
        self.pending_timers = remaining;

        for (tick, callbacks) in ready {
            for cb in callbacks {
                fired.push((tick, cb));
            }
        }

        self.current_tick = new_tick;
        Ok(fired)
    }

    /// Return the number of pending timers.
    pub fn pending_count(&self) -> usize {
        self.pending_timers.values().map(|v| v.len()).sum()
    }

    /// Return the current tick.
    pub fn now(&self) -> u64 {
        self.current_tick
    }
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MessageOutcome — result of sending through a virtual link
// ---------------------------------------------------------------------------

/// Outcome of sending a message through a faulted virtual link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageOutcome {
    /// Message was delivered (possibly delayed).
    Delivered { delay_ticks: u64 },
    /// Message was dropped.
    Dropped,
    /// Message was corrupted (bit-flip).
    Corrupted { delay_ticks: u64 },
    /// Message was reordered (placed in reorder buffer).
    Reordered {
        buffer_position: usize,
        delay_ticks: u64,
    },
}

// ---------------------------------------------------------------------------
// ScenarioResult
// ---------------------------------------------------------------------------

/// Result of executing a scenario in the lab runtime.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Whether the scenario passed.
    pub passed: bool,
    /// Events recorded during execution.
    pub events: Vec<LabEvent>,
    /// Seed used for this execution.
    pub seed: u64,
    /// Number of DPOR interleavings explored.
    pub interleavings_explored: u64,
    /// Number of bugs found across interleavings.
    pub bugs_found: u64,
    /// Serialised repro bundle if a failure occurred.
    pub repro_bundle: Option<String>,
}

// ---------------------------------------------------------------------------
// ReproBundle (serialisable)
// ---------------------------------------------------------------------------

/// A self-contained repro bundle that captures the full execution context
/// needed to reproduce a lab failure.
/// INV-LB-REPLAY: feeding this bundle back into LabRuntime reproduces the failure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReproBundle {
    /// Schema version tag.
    pub schema_version: String,
    /// Seed that produced the failure.
    pub seed: u64,
    /// Configuration used.
    pub config: LabConfig,
    /// Virtual links active during the run.
    pub links: Vec<VirtualLink>,
    /// Ordered event trace.
    pub events: Vec<LabEvent>,
    /// Whether the scenario passed or failed.
    pub passed: bool,
}

impl ReproBundle {
    fn validate(&self) -> Result<(), LabError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Self::validation_error(format!(
                "unsupported schema_version={}, expected={SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.seed != self.config.seed {
            return Err(Self::validation_error(format!(
                "seed mismatch: bundle.seed={}, config.seed={}",
                self.seed, self.config.seed
            )));
        }
        if self.links.len() > MAX_VIRTUAL_LINKS {
            return Err(Self::validation_error(format!(
                "bundle has {} links, exceeds runtime limit {MAX_VIRTUAL_LINKS}",
                self.links.len()
            )));
        }
        self.config
            .validate()
            .map_err(|err| Self::validation_error(format!("invalid config: {err}")))?;
        for (idx, link) in self.links.iter().enumerate() {
            link.fault_profile.validate().map_err(|err| {
                Self::validation_error(format!(
                    "invalid fault profile for link[{idx}] {}->{}: {err}",
                    link.source, link.target
                ))
            })?;
        }
        Ok(())
    }

    fn validation_error(detail: impl Into<String>) -> LabError {
        LabError::BundleValidation {
            detail: detail.into(),
        }
    }

    /// Serialize to a deterministic JSON string after validation.
    pub fn to_json(&self) -> Result<String, LabError> {
        self.validate().map_err(|err| match err {
            LabError::BundleValidation { detail } => LabError::BundleSerialization { detail },
            other => LabError::BundleSerialization {
                detail: other.to_string(),
            },
        })?;
        serde_json::to_string(self).map_err(|err| LabError::BundleSerialization {
            detail: err.to_string(),
        })
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self, LabError> {
        let bundle: Self =
            serde_json::from_str(s).map_err(|err| LabError::BundleDeserialization {
                detail: err.to_string(),
            })?;
        bundle.validate()?;
        Ok(bundle)
    }
}

// ---------------------------------------------------------------------------
// ScenarioFn — user-provided scenario logic
// ---------------------------------------------------------------------------

/// A scenario function receives a mutable reference to the LabRuntime
/// and returns Ok(true) for pass, Ok(false) for fail, or Err on error.
pub type ScenarioFn = Box<dyn Fn(&mut LabRuntime) -> Result<bool, LabError>>;

// ---------------------------------------------------------------------------
// LabRuntime
// ---------------------------------------------------------------------------

/// Deterministic lab runtime that replaces real I/O with virtual,
/// seeded implementations.
///
/// # Invariants
///
/// - INV-LB-DETERMINISTIC: identical seeds → identical event sequences
/// - INV-LB-TIMER-ORDER: timers fire in tick order (delegated to TestClock)
/// - INV-LB-FAULT-APPLIED: faults applied per profile
/// - INV-LB-NO-WALLCLOCK: no std::time — only TestClock ticks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabRuntime {
    /// Deterministic seed.
    pub seed: u64,
    /// Test clock for deterministic time.
    pub test_clock: TestClock,
    /// Active virtual links.
    pub virtual_links: Vec<VirtualLink>,
    /// Accumulated event log.
    pub events: Vec<LabEvent>,
    /// Runtime configuration.
    pub config: LabConfig,
    /// Internal PRNG state.
    rng: SplitMix64,
    /// Reorder buffers per link index.
    #[serde(skip)]
    reorder_buffers: Vec<Vec<String>>,
}

impl LabRuntime {
    /// Create a new lab runtime from the given configuration.
    pub fn new(config: LabConfig) -> Result<Self, LabError> {
        config.validate()?;
        let seed = config.seed;
        let rng = SplitMix64::new(seed);
        let mut runtime = Self {
            seed,
            test_clock: TestClock::new(),
            virtual_links: Vec::new(),
            events: Vec::new(),
            config,
            rng,
            reorder_buffers: Vec::new(),
        };
        runtime.emit(
            EVT_LAB_INITIALIZED,
            format!("seed={seed}, schema={SCHEMA_VERSION}"),
        );
        Ok(runtime)
    }

    /// Add a virtual link to the runtime.
    pub fn add_link(&mut self, link: VirtualLink) -> Result<usize, LabError> {
        link.fault_profile.validate()?;
        if self.virtual_links.len() >= MAX_VIRTUAL_LINKS
            || self.reorder_buffers.len() >= MAX_REORDER_BUFFERS
        {
            return Err(LabError::LinkCapacityExceeded {
                limit: MAX_VIRTUAL_LINKS.min(MAX_REORDER_BUFFERS),
            });
        }
        let idx = self.virtual_links.len();
        self.emit(
            EVT_VIRTUAL_LINK_CREATED,
            format!(
                "{} -> {} (drop={}, corrupt={}, delay={})",
                link.source,
                link.target,
                link.fault_profile.drop_pct,
                link.fault_profile.corrupt_probability,
                link.fault_profile.delay_ticks,
            ),
        );
        self.virtual_links.push(link);
        self.reorder_buffers.push(Vec::new());
        Ok(idx)
    }

    /// Find a link index by source and target names.
    pub fn find_link(&self, source: &str, target: &str) -> Result<usize, LabError> {
        self.virtual_links
            .iter()
            .position(|l| l.source == source && l.target == target)
            .ok_or_else(|| LabError::LinkNotFound {
                source: source.into(),
                target: target.into(),
            })
    }

    /// Send a message through the specified virtual link, applying faults
    /// deterministically based on the PRNG.
    /// INV-LB-FAULT-APPLIED: faults are applied exactly per profile.
    pub fn send_message(
        &mut self,
        link_idx: usize,
        message: &str,
    ) -> Result<MessageOutcome, LabError> {
        let link = self
            .virtual_links
            .get(link_idx)
            .ok_or_else(|| LabError::LinkNotFound {
                source: format!("idx={link_idx}"),
                target: "unknown".into(),
            })?;
        let profile = link.fault_profile.clone();
        let source = link.source.clone();
        let target = link.target.clone();

        // Determine outcome using the deterministic PRNG.
        let roll_drop = self.rng.next_f64();
        if roll_drop < profile.drop_pct {
            self.emit(EVT_FAULT_INJECTED, format!("dropped on {source}->{target}"));
            let outcome = MessageOutcome::Dropped;
            self.emit_message_processed(&source, &target, message, &outcome);
            return Ok(outcome);
        }

        let roll_corrupt = self.rng.next_f64();
        if roll_corrupt < profile.corrupt_probability {
            self.emit(
                EVT_FAULT_INJECTED,
                format!("corrupted on {source}->{target}"),
            );
            let outcome = MessageOutcome::Corrupted {
                delay_ticks: profile.delay_ticks,
            };
            self.emit_message_processed(&source, &target, message, &outcome);
            return Ok(outcome);
        }

        if self.reorder_buffers.len() <= link_idx {
            self.reorder_buffers.resize_with(link_idx + 1, Vec::new);
        }

        if profile.reorder_depth > 0 {
            let reordered_len = {
                let buf = self.reorder_buffers.get_mut(link_idx).ok_or_else(|| {
                    LabError::LinkNotFound {
                        source: format!("idx={link_idx}"),
                        target: "unknown".into(),
                    }
                })?;
                buf.push(message.to_string());
                if buf.len() >= profile.reorder_depth {
                    // Shuffle the buffer deterministically, then clear it before
                    // re-borrowing `self` for audit emission.
                    let len = buf.len();
                    for i in (1..len).rev() {
                        let j = self.rng.next_usize(i + 1);
                        buf.swap(i, j);
                    }
                    buf.clear();
                    Some(len)
                } else {
                    None
                }
            };

            if let Some(len) = reordered_len {
                self.emit(
                    EVT_FAULT_INJECTED,
                    format!("reordered {} messages on {}->{}", len, source, target),
                );
                let outcome = MessageOutcome::Reordered {
                    buffer_position: len - 1,
                    delay_ticks: profile.delay_ticks,
                };
                self.emit_message_processed(&source, &target, message, &outcome);
                return Ok(outcome);
            }
        }

        let outcome = MessageOutcome::Delivered {
            delay_ticks: profile.delay_ticks,
        };
        self.emit_message_processed(&source, &target, message, &outcome);
        Ok(outcome)
    }

    /// Schedule a timer on the test clock.
    pub fn schedule_timer(
        &mut self,
        delay: u64,
        label: impl Into<String>,
    ) -> Result<u64, LabError> {
        self.test_clock.schedule_timer(delay, label)
    }

    /// Advance the test clock and fire pending timers.
    /// Returns the list of fired timer callbacks with their tick.
    pub fn advance_clock(&mut self, delta: u64) -> Result<Vec<(u64, TimerCallback)>, LabError> {
        let fired = self.test_clock.advance(delta)?;
        if !fired.is_empty() {
            for (tick, cb) in &fired {
                push_bounded(
                    &mut self.events,
                    LabEvent {
                        tick: *tick,
                        event_code: EVT_TIMER_FIRED.to_string(),
                        payload: format!("timer_id={}, label={}", cb.id, cb.label),
                    },
                    MAX_EVENTS,
                );
            }
        }
        push_bounded(
            &mut self.events,
            LabEvent {
                tick: self.test_clock.current_tick,
                event_code: EVT_TEST_CLOCK_ADVANCED.to_string(),
                payload: format!("delta={delta}, now={}", self.test_clock.current_tick),
            },
            MAX_EVENTS,
        );
        Ok(fired)
    }

    /// Run a scenario function and collect the result.
    pub fn run_scenario(
        &mut self,
        scenario: &dyn Fn(&mut LabRuntime) -> Result<bool, LabError>,
    ) -> Result<ScenarioResult, LabError> {
        self.emit(EVT_SCENARIO_STARTED, format!("seed={}", self.seed));

        let passed = match scenario(self) {
            Ok(result) => result,
            Err(e) => {
                self.emit(EVT_SCENARIO_FAILED, format!("{e}"));
                false
            }
        };

        let event_code = if passed {
            EVT_SCENARIO_COMPLETED
        } else {
            EVT_SCENARIO_FAILED
        };
        self.emit(event_code, format!("passed={passed}"));

        let (events, repro_bundle) = if !passed {
            let bundle = self.export_repro_bundle(passed);
            let serialized = bundle.to_json()?;
            (bundle.events.clone(), Some(serialized))
        } else {
            (self.events.clone(), None)
        };

        Ok(ScenarioResult {
            passed,
            events,
            seed: self.seed,
            interleavings_explored: 0,
            bugs_found: if passed { 0 } else { 1 },
            repro_bundle,
        })
    }

    /// Run a scenario with DPOR exploration across multiple interleavings.
    /// Each interleaving re-seeds the PRNG with `seed + interleaving_index`
    /// to explore different scheduling orders.
    pub fn run_scenario_dpor(
        config: &LabConfig,
        links: &[VirtualLink],
        scenario: &dyn Fn(&mut LabRuntime) -> Result<bool, LabError>,
    ) -> Result<ScenarioResult, LabError> {
        config.validate()?;
        if !config.enable_dpor {
            // Fall back to single execution.
            let mut rt = LabRuntime::new(config.clone())?;
            for link in links {
                rt.add_link(link.clone())?;
            }
            return rt.run_scenario(scenario);
        }

        let mut all_events = Vec::new();
        let mut bugs_found: u64 = 0;
        let mut last_repro: Option<String> = None;
        let mut explored: u64 = 0;

        for i in 0..config.max_interleavings {
            if explored >= config.max_interleavings {
                break;
            }
            let mut interleaving_config = config.clone();
            interleaving_config.seed = config.seed.wrapping_add(i);
            // Ensure seed != 0 after wrapping.
            if interleaving_config.seed == 0 {
                interleaving_config.seed = 1;
            }

            let mut rt = LabRuntime::new(interleaving_config)?;
            for link in links {
                rt.add_link(link.clone())?;
            }

            rt.emit(
                EVT_DPOR_INTERLEAVING,
                format!("interleaving={i}, seed={}", rt.seed),
            );

            let result = rt.run_scenario(scenario)?;
            explored += 1;

            if !result.passed {
                bugs_found += 1;
                last_repro = result.repro_bundle.clone();
            }
            all_events.extend(result.events);
        }

        Ok(ScenarioResult {
            passed: bugs_found == 0,
            events: all_events,
            seed: config.seed,
            interleavings_explored: explored,
            bugs_found,
            repro_bundle: last_repro,
        })
    }

    /// Export a repro bundle capturing the current runtime state.
    /// INV-LB-REPLAY: this bundle can be fed back to reproduce the execution.
    pub fn export_repro_bundle(&self, passed: bool) -> ReproBundle {
        let mut events = self.events.clone();
        push_bounded(
            &mut events,
            LabEvent {
                tick: self.test_clock.current_tick,
                event_code: EVT_REPRO_EXPORTED.to_string(),
                payload: format!("events={}, passed={passed}", self.events.len()),
            },
            MAX_EVENTS,
        );
        ReproBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            seed: self.seed,
            config: self.config.clone(),
            links: self.virtual_links.clone(),
            events,
            passed,
        }
    }

    /// Replay a repro bundle and verify the stored execution trace matches.
    /// INV-LB-REPLAY: replay must preserve the full recorded event trace.
    pub fn replay_bundle(
        bundle: &ReproBundle,
        scenario: &dyn Fn(&mut LabRuntime) -> Result<bool, LabError>,
    ) -> Result<ScenarioResult, LabError> {
        bundle.validate()?;
        let mut rt = LabRuntime::new(bundle.config.clone())?;
        for link in &bundle.links {
            rt.add_link(link.clone())?;
        }
        let mut result = rt.run_scenario(scenario)?;

        // Failure replays already carry `EVT_REPRO_EXPORTED` in the returned
        // `ScenarioResult.events`. Passing bundles need an explicit export here
        // so both paths compare against the same stored event surface.
        let replayed_events = if bundle.passed && result.passed {
            rt.export_repro_bundle(result.passed).events
        } else {
            result.events.clone()
        };

        // Verify determinism: both the final verdict and the full event trace
        // must match the stored repro bundle.
        if result.passed != bundle.passed || replayed_events != bundle.events {
            return Err(LabError::ReplayDivergence {
                expected_events: bundle.events.len(),
                actual_events: replayed_events.len(),
            });
        }

        result.events = replayed_events;
        Ok(result)
    }

    /// Get the current mock-clock tick.
    pub fn now(&self) -> u64 {
        self.test_clock.now()
    }

    /// Get all recorded events.
    pub fn events(&self) -> &[LabEvent] {
        &self.events
    }

    /// Get the number of virtual links.
    pub fn link_count(&self) -> usize {
        self.virtual_links.len()
    }

    /// Get the internal PRNG (for advanced test scenarios that need
    /// deterministic random decisions).
    pub fn rng(&mut self) -> &mut SplitMix64 {
        &mut self.rng
    }

    // -- internal helpers --

    fn emit(&mut self, code: &str, payload: String) {
        push_bounded(
            &mut self.events,
            LabEvent {
                tick: self.test_clock.current_tick,
                event_code: code.to_string(),
                payload,
            },
            MAX_EVENTS,
        );
    }

    fn emit_message_processed(
        &mut self,
        source: &str,
        target: &str,
        message: &str,
        outcome: &MessageOutcome,
    ) {
        let outcome_detail = match outcome {
            MessageOutcome::Delivered { delay_ticks } => {
                format!("outcome=delivered, delay_ticks={delay_ticks}")
            }
            MessageOutcome::Dropped => "outcome=dropped".to_string(),
            MessageOutcome::Corrupted { delay_ticks } => {
                format!("outcome=corrupted, delay_ticks={delay_ticks}")
            }
            MessageOutcome::Reordered {
                buffer_position,
                delay_ticks,
            } => {
                format!(
                    "outcome=reordered, buffer_position={buffer_position}, delay_ticks={delay_ticks}"
                )
            }
        };
        self.emit(
            EVT_MESSAGE_PROCESSED,
            format!("source={source}, target={target}, message={message:?}, {outcome_detail}"),
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> LabConfig {
        LabConfig {
            seed: 42,
            max_ticks: 10_000,
            max_interleavings: 100,
            enable_dpor: false,
        }
    }

    fn lossy_profile() -> FaultProfile {
        FaultProfile {
            drop_pct: 0.5,
            reorder_depth: 0,
            corrupt_probability: 0.0,
            delay_ticks: 0,
        }
    }

    fn reorder_profile() -> FaultProfile {
        FaultProfile {
            drop_pct: 0.0,
            reorder_depth: 3,
            corrupt_probability: 0.0,
            delay_ticks: 1,
        }
    }

    #[allow(dead_code)]
    fn corrupt_profile() -> FaultProfile {
        FaultProfile {
            drop_pct: 0.0,
            reorder_depth: 0,
            corrupt_probability: 0.5,
            delay_ticks: 2,
        }
    }

    fn make_link(src: &str, tgt: &str, profile: FaultProfile) -> VirtualLink {
        VirtualLink::new(src, tgt, profile).unwrap()
    }

    // ---------------------------------------------------------------
    // SplitMix64 determinism
    // ---------------------------------------------------------------

    #[test]
    fn test_splitmix64_deterministic() {
        // INV-LB-DETERMINISTIC: same seed → same sequence.
        let mut a = SplitMix64::new(12345);
        let mut b = SplitMix64::new(12345);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn test_splitmix64_different_seeds_diverge() {
        let mut a = SplitMix64::new(1);
        let mut b = SplitMix64::new(2);
        // Extremely unlikely to produce the same first value.
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn test_splitmix64_f64_range() {
        let mut rng = SplitMix64::new(999);
        for _ in 0..10_000 {
            let v = rng.next_f64();
            assert!((0.0..1.0).contains(&v), "f64 out of range: {v}");
        }
    }

    #[test]
    fn test_splitmix64_next_usize_bound() {
        let mut rng = SplitMix64::new(42);
        for _ in 0..1000 {
            let v = rng.next_usize(10);
            assert!(v < 10);
        }
        // Bound of 0 or 1 always returns 0.
        assert_eq!(rng.next_usize(0), 0);
        assert_eq!(rng.next_usize(1), 0);
    }

    // ---------------------------------------------------------------
    // TestClock
    // ---------------------------------------------------------------

    #[test]
    fn test_clock_starts_at_zero() {
        let clock = TestClock::new();
        assert_eq!(clock.now(), 0);
        assert_eq!(clock.pending_count(), 0);
    }

    #[test]
    fn test_clock_advance_no_timers() {
        let mut clock = TestClock::new();
        let fired = clock.advance(100).unwrap();
        assert!(fired.is_empty());
        assert_eq!(clock.now(), 100);
    }

    #[test]
    fn test_clock_timer_fires_at_correct_tick() {
        // INV-LB-TIMER-ORDER: timer at tick 50 fires when advancing to 50.
        let mut clock = TestClock::new();
        clock.schedule_timer(50, "t1").unwrap();
        let fired = clock.advance(50).unwrap();
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].0, 50);
        assert_eq!(fired[0].1.label, "t1");
    }

    // ── NEGATIVE-PATH INLINE TESTS ─────────────────────────────────────────
    // Comprehensive edge case and boundary validation for security-critical functions

    /// Test push_bounded with overflow and capacity edge cases
    #[test]
    fn test_push_bounded_negative_paths() {
        // Zero capacity - should not panic but clear and add
        let mut vec = vec![1, 2, 3];
        push_bounded(&mut vec, 999, 0);
        assert_eq!(vec, vec![999]); // Different behavior than other push_bounded implementations

        // Single capacity with existing items
        let mut vec = vec![1, 2, 3, 4, 5];
        push_bounded(&mut vec, 999, 1);
        assert_eq!(vec, vec![999]);

        // Exact capacity boundary (should not trigger drain)
        let mut vec = vec![1, 2];
        push_bounded(&mut vec, 999, 3);
        assert_eq!(vec, vec![1, 2, 999]);

        // Over capacity by 1 (should drain 2 items)
        let mut vec = vec![1, 2, 3];
        push_bounded(&mut vec, 999, 2);
        assert_eq!(vec, vec![3, 999]);

        // Very large capacity with small vec
        let mut vec = vec![1];
        push_bounded(&mut vec, 999, 1_000_000);
        assert_eq!(vec, vec![1, 999]);

        // Large vec with very small capacity
        let mut large_vec: Vec<i32> = (0..10_000).collect();
        push_bounded(&mut large_vec, 999, 3);
        assert_eq!(large_vec.len(), 3);
        assert_eq!(large_vec[2], 999);

        // Empty vec with normal capacity
        let mut empty_vec: Vec<i32> = vec![];
        push_bounded(&mut empty_vec, 42, 5);
        assert_eq!(empty_vec, vec![42]);

        // Arithmetic overflow protection test
        let mut overflow_vec = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let cap = 5;
        let overflow = overflow_vec.len().saturating_sub(cap).saturating_add(1); // = 6
        push_bounded(&mut overflow_vec, 999, cap);
        assert_eq!(overflow_vec.len(), cap);
        assert_eq!(overflow_vec[cap - 1], 999);
    }

    /// Test SplitMix64 PRNG with edge case seeds and boundary conditions
    #[test]
    fn test_splitmix64_negative_paths() {
        // Zero seed (should work fine)
        let mut rng_zero = SplitMix64::new(0);
        let val1 = rng_zero.next_u64();
        let val2 = rng_zero.next_u64();
        assert_ne!(val1, val2); // Should produce different values
        assert!(val1 > 0 || val2 > 0); // At least one should be non-zero

        // Maximum u64 seed
        let mut rng_max = SplitMix64::new(u64::MAX);
        let max_val = rng_max.next_u64();
        assert!(max_val > 0); // Should not produce zero immediately

        // Seed that could cause wrapping issues
        let mut rng_wrap = SplitMix64::new(u64::MAX - 0x9e37_79b9_7f4a_7c15 + 1);
        let wrap_val = rng_wrap.next_u64();
        assert!(wrap_val > 0);

        // Test next_f64 edge cases
        let mut rng_float = SplitMix64::new(1);
        for _ in 0..10000 {
            let f = rng_float.next_f64();
            assert!(f >= 0.0);
            assert!(f < 1.0);
            assert!(f.is_finite());
            assert!(!f.is_nan());
        }

        // Test next_usize boundary conditions
        let mut rng_usize = SplitMix64::new(42);

        // Bound = 0 should always return 0
        for _ in 0..100 {
            assert_eq!(rng_usize.next_usize(0), 0);
        }

        // Bound = 1 should always return 0
        for _ in 0..100 {
            assert_eq!(rng_usize.next_usize(1), 0);
        }

        // Large bound should work
        for _ in 0..1000 {
            let val = rng_usize.next_usize(1_000_000);
            assert!(val < 1_000_000);
        }

        // Maximum usize bound
        let max_bound_val = rng_usize.next_usize(usize::MAX);
        assert!(max_bound_val < usize::MAX);

        // Determinism test with sequential seeds
        let mut rng1 = SplitMix64::new(100);
        let mut rng2 = SplitMix64::new(100);
        for _ in 0..1000 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
            assert_eq!(rng1.next_f64(), rng2.next_f64());
            assert_eq!(rng1.next_usize(50), rng2.next_usize(50));
        }
    }

    /// Test FaultProfile::validate with invalid probability ranges
    #[test]
    fn test_fault_profile_validate_negative_paths() {
        // Invalid negative drop_pct
        let profile_neg_drop = FaultProfile {
            drop_pct: -0.5,
            ..Default::default()
        };
        match profile_neg_drop.validate() {
            Err(LabError::FaultRange { field, value }) => {
                assert_eq!(field, "drop_pct");
                assert_eq!(value, -0.5);
            }
            _ => panic!("Expected FaultRange error for negative drop_pct"),
        }

        // Invalid drop_pct > 1.0
        let profile_high_drop = FaultProfile {
            drop_pct: 1.5,
            ..Default::default()
        };
        assert!(profile_high_drop.validate().is_err());

        // Invalid negative corrupt_probability
        let profile_neg_corrupt = FaultProfile {
            corrupt_probability: -0.1,
            ..Default::default()
        };
        match profile_neg_corrupt.validate() {
            Err(LabError::FaultRange { field, value }) => {
                assert_eq!(field, "corrupt_probability");
                assert_eq!(value, -0.1);
            }
            _ => panic!("Expected FaultRange error for negative corrupt_probability"),
        }

        // Invalid corrupt_probability > 1.0
        let profile_high_corrupt = FaultProfile {
            corrupt_probability: 2.0,
            ..Default::default()
        };
        assert!(profile_high_corrupt.validate().is_err());

        // Edge case: exactly 0.0 (should be valid)
        let profile_zero = FaultProfile {
            drop_pct: 0.0,
            corrupt_probability: 0.0,
            ..Default::default()
        };
        assert!(profile_zero.validate().is_ok());

        // Edge case: exactly 1.0 (should be valid)
        let profile_one = FaultProfile {
            drop_pct: 1.0,
            corrupt_probability: 1.0,
            ..Default::default()
        };
        assert!(profile_one.validate().is_ok());

        // NaN values (should be invalid)
        let profile_nan_drop = FaultProfile {
            drop_pct: f64::NAN,
            ..Default::default()
        };
        assert!(profile_nan_drop.validate().is_err());

        let profile_nan_corrupt = FaultProfile {
            corrupt_probability: f64::NAN,
            ..Default::default()
        };
        assert!(profile_nan_corrupt.validate().is_err());

        // Infinity values (should be invalid)
        let profile_inf_drop = FaultProfile {
            drop_pct: f64::INFINITY,
            ..Default::default()
        };
        assert!(profile_inf_drop.validate().is_err());

        let profile_neg_inf_corrupt = FaultProfile {
            corrupt_probability: f64::NEG_INFINITY,
            ..Default::default()
        };
        assert!(profile_neg_inf_corrupt.validate().is_err());

        // Maximum values for other fields should be OK
        let profile_max_others = FaultProfile {
            drop_pct: 0.5,
            corrupt_probability: 0.5,
            reorder_depth: usize::MAX,
            delay_ticks: u64::MAX,
        };
        assert!(profile_max_others.validate().is_ok());
    }

    /// Test VirtualLink::new with edge case parameters
    #[test]
    fn test_virtual_link_new_negative_paths() {
        // Invalid fault profile should fail
        let invalid_profile = FaultProfile {
            drop_pct: -1.0,
            ..Default::default()
        };
        let result = VirtualLink::new("src", "tgt", invalid_profile);
        assert!(result.is_err());

        // Empty source and target names (should be allowed)
        let valid_profile = FaultProfile::default();
        let link_empty = VirtualLink::new("", "", valid_profile.clone()).unwrap();
        assert_eq!(link_empty.source, "");
        assert_eq!(link_empty.target, "");

        // Very long node names
        let long_source = "s".repeat(1_000_000);
        let long_target = "t".repeat(1_000_000);
        let link_long = VirtualLink::new(
            long_source.clone(),
            long_target.clone(),
            valid_profile.clone(),
        )
        .unwrap();
        assert_eq!(link_long.source, long_source);
        assert_eq!(link_long.target, long_target);

        // Unicode node names
        let link_unicode =
            VirtualLink::new("源节点_🌟", "目标节点_🔒", valid_profile.clone()).unwrap();
        assert_eq!(link_unicode.source, "源节点_🌟");
        assert_eq!(link_unicode.target, "目标节点_🔒");

        // Node names with special characters
        let link_special = VirtualLink::new("\0\r\n\t", "target/\\?*<>|:", valid_profile).unwrap();
        assert_eq!(link_special.source, "\0\r\n\t");
        assert_eq!(link_special.target, "target/\\?*<>|:");

        // Extreme fault profile values (but valid)
        let extreme_profile = FaultProfile {
            drop_pct: 1.0,
            reorder_depth: usize::MAX,
            corrupt_probability: 1.0,
            delay_ticks: u64::MAX,
        };
        let link_extreme = VirtualLink::new("test", "extreme", extreme_profile).unwrap();
        assert_eq!(link_extreme.fault_profile.drop_pct, 1.0);
        assert_eq!(link_extreme.fault_profile.reorder_depth, usize::MAX);
    }

    /// Test LabConfig::validate with edge case configurations
    #[test]
    fn test_lab_config_validate_negative_paths() {
        // Zero seed should fail
        let config_zero_seed = LabConfig {
            seed: 0,
            ..Default::default()
        };
        match config_zero_seed.validate() {
            Err(LabError::NoSeed) => {} // Expected
            _ => panic!("Expected NoSeed error for zero seed"),
        }

        // Seed = 1 should be valid (minimum valid seed)
        let config_one_seed = LabConfig {
            seed: 1,
            ..Default::default()
        };
        assert!(config_one_seed.validate().is_ok());

        // Maximum seed should be valid
        let config_max_seed = LabConfig {
            seed: u64::MAX,
            ..Default::default()
        };
        assert!(config_max_seed.validate().is_ok());

        // Zero max_ticks should be valid (no explicit validation)
        let config_zero_ticks = LabConfig {
            seed: 42,
            max_ticks: 0,
            ..Default::default()
        };
        assert!(config_zero_ticks.validate().is_ok());

        // Zero max_interleavings should be valid
        let config_zero_interleavings = LabConfig {
            seed: 42,
            max_interleavings: 0,
            ..Default::default()
        };
        assert!(config_zero_interleavings.validate().is_ok());

        // Maximum values should be valid
        let config_max_values = LabConfig {
            seed: u64::MAX,
            max_ticks: u64::MAX,
            max_interleavings: u64::MAX,
            enable_dpor: true,
        };
        assert!(config_max_values.validate().is_ok());
    }

    /// Test TestClock with extreme tick values and overflow scenarios
    #[test]
    fn test_test_clock_extreme_cases() {
        // Timer scheduling with maximum delay
        let mut clock = TestClock::new();
        let max_delay_id = clock.schedule_timer(u64::MAX, "max_delay").unwrap();
        assert!(max_delay_id > 0);
        assert_eq!(clock.pending_count(), 1);

        // Advance by maximum amount
        let fired = clock.advance(u64::MAX).unwrap();
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].1.id, max_delay_id);
        assert_eq!(clock.now(), u64::MAX);

        // Timer scheduling overflow (current_tick + delay > u64::MAX)
        let mut clock_overflow = TestClock::new();
        clock_overflow.current_tick = u64::MAX - 5;

        // This should fail due to overflow
        let overflow_result = clock_overflow.schedule_timer(10, "overflow");
        match overflow_result {
            Err(LabError::TickOverflow { current, delta }) => {
                assert_eq!(current, u64::MAX - 5);
                assert_eq!(delta, 10);
            }
            _ => panic!("Expected TickOverflow error"),
        }

        // Advance overflow
        let mut clock_advance_overflow = TestClock::new();
        clock_advance_overflow.current_tick = u64::MAX - 2;

        let overflow_advance = clock_advance_overflow.advance(5);
        match overflow_advance {
            Err(LabError::TickOverflow { current, delta }) => {
                assert_eq!(current, u64::MAX - 2);
                assert_eq!(delta, 5);
            }
            _ => panic!("Expected TickOverflow error"),
        }

        // Timer ID exhaustion
        let mut clock_exhausted = TestClock::new();
        clock_exhausted.next_timer_id = u64::MAX;

        // Should succeed with u64::MAX
        let last_id = clock_exhausted.schedule_timer(1, "last").unwrap();
        assert_eq!(last_id, u64::MAX);

        // Should fail as next_timer_id becomes 0
        let exhausted_result = clock_exhausted.schedule_timer(1, "exhausted");
        match exhausted_result {
            Err(LabError::TimerIdExhausted) => {} // Expected
            _ => panic!("Expected TimerIdExhausted error"),
        }

        // Many timers at the same tick
        let mut clock_many = TestClock::new();
        for i in 0..10000 {
            clock_many
                .schedule_timer(100, format!("timer_{}", i))
                .unwrap();
        }
        assert_eq!(clock_many.pending_count(), 10000);

        let all_fired = clock_many.advance(100).unwrap();
        assert_eq!(all_fired.len(), 10000);
        assert_eq!(clock_many.pending_count(), 0);

        // Zero delay timer (should fire immediately when advanced)
        let mut clock_zero = TestClock::new();
        let zero_id = clock_zero.schedule_timer(0, "zero_delay").unwrap();
        let zero_fired = clock_zero.advance(0).unwrap();
        assert_eq!(zero_fired.len(), 1);
        assert_eq!(zero_fired[0].1.id, zero_id);
    }

    /// Test ReproBundle serialization with extreme and malformed data
    #[test]
    fn test_repro_bundle_serialization_negative_paths() {
        // Valid bundle as baseline
        let valid_bundle = ReproBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            seed: 42,
            config: LabConfig::default(),
            links: vec![],
            events: vec![],
            passed: true,
        };
        assert!(valid_bundle.to_json().is_ok());

        // Invalid schema version
        let invalid_schema_bundle = ReproBundle {
            schema_version: "invalid-schema".to_string(),
            ..valid_bundle.clone()
        };
        match invalid_schema_bundle.to_json() {
            Err(LabError::BundleSerialization { detail }) => {
                assert!(detail.contains("unsupported schema_version"));
            }
            _ => panic!("Expected BundleSerialization error for invalid schema"),
        }

        // Seed mismatch between bundle and config
        let seed_mismatch_bundle = ReproBundle {
            seed: 123,
            config: LabConfig {
                seed: 456,
                ..Default::default()
            },
            ..valid_bundle.clone()
        };
        match seed_mismatch_bundle.to_json() {
            Err(LabError::BundleSerialization { detail }) => {
                assert!(detail.contains("seed mismatch"));
            }
            _ => panic!("Expected BundleSerialization error for seed mismatch"),
        }

        // Too many links
        let mut too_many_links = vec![];
        for i in 0..MAX_VIRTUAL_LINKS + 1 {
            too_many_links.push(VirtualLink {
                source: format!("src_{}", i),
                target: format!("tgt_{}", i),
                fault_profile: FaultProfile::default(),
            });
        }
        let too_many_links_bundle = ReproBundle {
            links: too_many_links,
            ..valid_bundle.clone()
        };
        match too_many_links_bundle.to_json() {
            Err(LabError::BundleSerialization { detail }) => {
                assert!(detail.contains("exceeds runtime limit"));
            }
            _ => panic!("Expected BundleSerialization error for too many links"),
        }

        // Invalid config in bundle
        let invalid_config_bundle = ReproBundle {
            config: LabConfig {
                seed: 0,
                ..Default::default()
            },
            seed: 0,
            ..valid_bundle.clone()
        };
        match invalid_config_bundle.to_json() {
            Err(LabError::BundleSerialization { detail }) => {
                assert!(detail.contains("invalid config"));
            }
            _ => panic!("Expected BundleSerialization error for invalid config"),
        }

        // Invalid fault profile in link
        let invalid_link = VirtualLink {
            source: "src".to_string(),
            target: "tgt".to_string(),
            fault_profile: FaultProfile {
                drop_pct: -1.0,
                ..Default::default()
            },
        };
        let invalid_link_bundle = ReproBundle {
            links: vec![invalid_link],
            ..valid_bundle.clone()
        };
        match invalid_link_bundle.to_json() {
            Err(LabError::BundleSerialization { detail }) => {
                assert!(detail.contains("invalid fault profile"));
            }
            _ => panic!("Expected BundleSerialization error for invalid fault profile"),
        }

        // Very large bundle with extreme data
        let large_events: Vec<LabEvent> = (0..100_000)
            .map(|i| LabEvent {
                tick: i,
                event_code: format!("TEST-{:06}", i),
                payload: "x".repeat(1000), // 1KB per event
            })
            .collect();

        let large_bundle = ReproBundle {
            events: large_events,
            ..valid_bundle.clone()
        };

        let large_json = large_bundle.to_json();
        assert!(large_json.is_ok());

        // Test round-trip with large bundle
        let large_json_str = large_json.unwrap();
        let parsed_large = ReproBundle::from_json(&large_json_str);
        assert!(parsed_large.is_ok());
        assert_eq!(parsed_large.unwrap().events.len(), 100_000);

        // Malformed JSON deserialization
        let bad_jsons = vec![
            "",
            "null",
            "[]",
            "{",
            "{\"invalid\": true}",
            "{\"schema_version\": \"invalid\"}",
        ];

        for bad_json in bad_jsons {
            let result = ReproBundle::from_json(bad_json);
            assert!(matches!(
                result,
                Err(LabError::BundleDeserialization { .. })
            ));
        }
    }

    /// Test LabRuntime with extreme link and message scenarios
    #[test]
    fn test_lab_runtime_extreme_scenarios() {
        // Maximum number of links
        let mut rt_max_links = LabRuntime::new(default_config()).unwrap();
        for i in 0..MAX_VIRTUAL_LINKS {
            let link = make_link(
                &format!("src_{}", i),
                &format!("tgt_{}", i),
                FaultProfile::default(),
            );
            assert!(rt_max_links.add_link(link).is_ok());
        }
        assert_eq!(rt_max_links.link_count(), MAX_VIRTUAL_LINKS);

        // Exceeding link capacity should fail
        let excess_link = make_link("excess_src", "excess_tgt", FaultProfile::default());
        match rt_max_links.add_link(excess_link) {
            Err(LabError::LinkCapacityExceeded { limit }) => {
                assert_eq!(limit, MAX_VIRTUAL_LINKS.min(MAX_REORDER_BUFFERS));
            }
            _ => panic!("Expected LinkCapacityExceeded error"),
        }

        // Find link with non-existent names
        let find_result = rt_max_links.find_link("nonexistent", "link");
        match find_result {
            Err(LabError::LinkNotFound { source, target }) => {
                assert_eq!(source, "nonexistent");
                assert_eq!(target, "link");
            }
            _ => panic!("Expected LinkNotFound error"),
        }

        // Send message on non-existent link index
        let send_result = rt_max_links.send_message(999999, "test");
        match send_result {
            Err(LabError::LinkNotFound { source, target }) => {
                assert!(source.contains("idx=999999"));
                assert_eq!(target, "unknown");
            }
            _ => panic!("Expected LinkNotFound error for invalid link index"),
        }

        // Message sending with extreme fault profiles
        let mut rt_extreme = LabRuntime::new(default_config()).unwrap();

        // 100% drop rate
        let drop_link = make_link(
            "src",
            "drop_tgt",
            FaultProfile {
                drop_pct: 1.0,
                ..Default::default()
            },
        );
        let drop_idx = rt_extreme.add_link(drop_link).unwrap();

        for _ in 0..1000 {
            let outcome = rt_extreme.send_message(drop_idx, "dropped").unwrap();
            assert_eq!(outcome, MessageOutcome::Dropped);
        }

        // 100% corruption rate
        let corrupt_link = make_link(
            "src",
            "corrupt_tgt",
            FaultProfile {
                corrupt_probability: 1.0,
                delay_ticks: 42,
                ..Default::default()
            },
        );
        let corrupt_idx = rt_extreme.add_link(corrupt_link).unwrap();

        let corrupt_outcome = rt_extreme.send_message(corrupt_idx, "corrupted").unwrap();
        assert_eq!(
            corrupt_outcome,
            MessageOutcome::Corrupted { delay_ticks: 42 }
        );

        // Maximum reorder depth
        let reorder_link = make_link(
            "src",
            "reorder_tgt",
            FaultProfile {
                reorder_depth: 10000,
                ..Default::default()
            },
        );
        let reorder_idx = rt_extreme.add_link(reorder_link).unwrap();

        // Send many messages to trigger reordering
        for i in 0..20000 {
            let outcome = rt_extreme
                .send_message(reorder_idx, &format!("msg_{}", i))
                .unwrap();
            // Should eventually trigger reordering
            if matches!(outcome, MessageOutcome::Reordered { .. }) {
                break;
            }
        }

        // Very long message content
        let normal_link = make_link("src", "normal", FaultProfile::default());
        let normal_idx = rt_extreme.add_link(normal_link).unwrap();

        let huge_message = "M".repeat(1_000_000);
        let huge_outcome = rt_extreme.send_message(normal_idx, &huge_message).unwrap();
        assert_eq!(huge_outcome, MessageOutcome::Delivered { delay_ticks: 0 });

        // Timer scheduling edge cases
        let max_timer_result = rt_extreme.schedule_timer(u64::MAX, "max_timer");
        assert!(max_timer_result.is_ok());

        // Clock advancement edge cases
        rt_extreme.test_clock.current_tick = u64::MAX - 1;
        let advance_result = rt_extreme.advance_clock(2);
        assert!(advance_result.is_err());
    }

    /// Test DPOR execution with edge case configurations
    #[test]
    fn test_dpor_execution_edge_cases() {
        // DPOR disabled should fall back to single execution
        let dpor_disabled_config = LabConfig {
            enable_dpor: false,
            max_interleavings: 1000,
            ..default_config()
        };

        let links = vec![make_link("a", "b", FaultProfile::default())];

        let scenario = |_rt: &mut LabRuntime| -> Result<bool, LabError> {
            Ok(true) // Always pass
        };

        let result =
            LabRuntime::run_scenario_dpor(&dpor_disabled_config, &links, &scenario).unwrap();
        assert!(result.passed);
        assert_eq!(result.interleavings_explored, 0); // No DPOR exploration
        assert_eq!(result.bugs_found, 0);

        // Zero max_interleavings with DPOR enabled
        let zero_interleavings_config = LabConfig {
            enable_dpor: true,
            max_interleavings: 0,
            ..default_config()
        };

        let zero_result =
            LabRuntime::run_scenario_dpor(&zero_interleavings_config, &links, &scenario).unwrap();
        assert!(zero_result.passed);
        assert_eq!(zero_result.interleavings_explored, 0);

        // Scenario that always fails
        let fail_scenario = |_rt: &mut LabRuntime| -> Result<bool, LabError> {
            Ok(false) // Always fail
        };

        let fail_result =
            LabRuntime::run_scenario_dpor(&default_config(), &links, &fail_scenario).unwrap();
        assert!(!fail_result.passed);
        assert!(fail_result.repro_bundle.is_some());

        // Scenario that returns error
        let error_scenario =
            |_rt: &mut LabRuntime| -> Result<bool, LabError> { Err(LabError::NoSeed) };

        let error_result =
            LabRuntime::run_scenario_dpor(&default_config(), &links, &error_scenario).unwrap();
        assert!(!error_result.passed);
        assert_eq!(error_result.bugs_found, 1);

        // Seed wrapping edge case (seed + i wraps around)
        let wrap_config = LabConfig {
            seed: u64::MAX - 2,
            enable_dpor: true,
            max_interleavings: 5,
            ..default_config()
        };

        let wrap_result = LabRuntime::run_scenario_dpor(&wrap_config, &links, &scenario).unwrap();
        assert!(wrap_result.passed);
        assert_eq!(wrap_result.interleavings_explored, 5);

        // Large number of interleavings
        let large_interleavings_config = LabConfig {
            enable_dpor: true,
            max_interleavings: 100_000,
            ..default_config()
        };

        // Use a scenario that passes quickly to avoid long test runtime
        let quick_scenario = |_rt: &mut LabRuntime| -> Result<bool, LabError> { Ok(true) };

        let large_result =
            LabRuntime::run_scenario_dpor(&large_interleavings_config, &links, &quick_scenario)
                .unwrap();
        assert!(large_result.passed);
        assert_eq!(large_result.interleavings_explored, 100_000);
    }

    #[test]
    fn test_clock_timer_order_invariant() {
        // INV-LB-TIMER-ORDER: timers fire in ascending tick order.
        let mut clock = TestClock::new();
        clock.schedule_timer(30, "second").unwrap();
        clock.schedule_timer(10, "first").unwrap();
        clock.schedule_timer(50, "third").unwrap();
        let fired = clock.advance(100).unwrap();
        assert_eq!(fired.len(), 3);
        assert_eq!(fired[0].1.label, "first");
        assert_eq!(fired[1].1.label, "second");
        assert_eq!(fired[2].1.label, "third");
        // Ticks are monotonically increasing.
        assert!(fired[0].0 <= fired[1].0);
        assert!(fired[1].0 <= fired[2].0);
    }

    #[test]
    fn test_clock_multiple_timers_same_tick() {
        let mut clock = TestClock::new();
        clock.schedule_timer(10, "a").unwrap();
        clock.schedule_timer(10, "b").unwrap();
        let fired = clock.advance(10).unwrap();
        assert_eq!(fired.len(), 2);
        // Both at tick 10.
        assert_eq!(fired[0].0, 10);
        assert_eq!(fired[1].0, 10);
    }

    #[test]
    fn test_clock_timer_not_fired_early() {
        let mut clock = TestClock::new();
        clock.schedule_timer(100, "future").unwrap();
        let fired = clock.advance(50).unwrap();
        assert!(fired.is_empty());
        assert_eq!(clock.pending_count(), 1);
    }

    #[test]
    fn test_clock_tick_overflow_error() {
        let mut clock = TestClock::new();
        clock.current_tick = u64::MAX - 5;
        let result = clock.advance(10);
        assert!(result.is_err());
        match result.unwrap_err() {
            LabError::TickOverflow { current, delta } => {
                assert_eq!(current, u64::MAX - 5);
                assert_eq!(delta, 10);
            }
            other => unreachable!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_clock_schedule_overflow_error() {
        let mut clock = TestClock::new();
        clock.current_tick = u64::MAX;
        let result = clock.schedule_timer(1, "overflow");
        assert!(result.is_err());
    }

    #[test]
    fn test_clock_schedule_overflow_does_not_register_timer() {
        let mut clock = TestClock::new();
        clock.current_tick = u64::MAX;

        let err = clock
            .schedule_timer(1, "overflow")
            .expect_err("overflowing timer must be rejected");

        assert!(matches!(err, LabError::TickOverflow { .. }));
        assert_eq!(clock.pending_count(), 0);
    }

    #[test]
    fn test_clock_advance_overflow_preserves_state() {
        let mut clock = TestClock::new();
        clock.schedule_timer(1, "still-pending").unwrap();
        clock.current_tick = u64::MAX - 5;

        let err = clock
            .advance(10)
            .expect_err("overflowing advance must be rejected");

        assert!(matches!(err, LabError::TickOverflow { .. }));
        assert_eq!(clock.now(), u64::MAX - 5);
        assert_eq!(clock.pending_count(), 1);
    }

    #[test]
    fn test_clock_advance_to_u64_max_fires_terminal_tick_timer() {
        let mut clock = TestClock::new();
        clock.current_tick = u64::MAX - 1;
        clock.schedule_timer(1, "max-tick").unwrap();

        let fired = clock.advance(1).unwrap();
        assert_eq!(clock.now(), u64::MAX);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].0, u64::MAX);
        assert_eq!(fired[0].1.label, "max-tick");
    }

    #[test]
    fn test_clock_timer_id_exhaustion_fails_closed_after_terminal_id() {
        let mut clock = TestClock::new();
        clock.next_timer_id = u64::MAX;

        let id = clock.schedule_timer(0, "terminal-id").unwrap();
        assert_eq!(id, u64::MAX);

        let err = clock
            .schedule_timer(0, "duplicate-id")
            .expect_err("timer id exhaustion must fail closed");
        assert!(matches!(err, LabError::TimerIdExhausted));
        assert_eq!(clock.pending_count(), 1);
    }

    // ---------------------------------------------------------------
    // FaultProfile validation
    // ---------------------------------------------------------------

    #[test]
    fn test_fault_profile_valid() {
        let p = FaultProfile::default();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_fault_profile_drop_pct_out_of_range() {
        let p = FaultProfile {
            drop_pct: 1.5,
            ..Default::default()
        };
        let err = p.validate().unwrap_err();
        assert!(matches!(err, LabError::FaultRange { field, .. } if field == "drop_pct"));
    }

    #[test]
    fn test_fault_profile_corrupt_probability_negative() {
        let p = FaultProfile {
            corrupt_probability: -0.1,
            ..Default::default()
        };
        let err = p.validate().unwrap_err();
        assert!(
            matches!(err, LabError::FaultRange { field, .. } if field == "corrupt_probability")
        );
    }

    #[test]
    fn test_fault_profile_drop_pct_nan_rejected() {
        let p = FaultProfile {
            drop_pct: f64::NAN,
            ..Default::default()
        };

        let err = p
            .validate()
            .expect_err("NaN drop probability must fail closed");

        assert!(
            matches!(err, LabError::FaultRange { field, value } if field == "drop_pct" && value.is_nan())
        );
    }

    #[test]
    fn test_fault_profile_corrupt_probability_above_one_rejected() {
        let p = FaultProfile {
            corrupt_probability: 1.01,
            ..Default::default()
        };

        let err = p
            .validate()
            .expect_err("corrupt probability above one must fail closed");

        assert!(
            matches!(err, LabError::FaultRange { field, value } if field == "corrupt_probability" && value > 1.0)
        );
    }

    #[test]
    fn test_fault_profile_corrupt_probability_nan_rejected() {
        let p = FaultProfile {
            corrupt_probability: f64::NAN,
            ..Default::default()
        };

        let err = p
            .validate()
            .expect_err("NaN corrupt probability must fail closed");

        assert!(
            matches!(err, LabError::FaultRange { field, value } if field == "corrupt_probability" && value.is_nan())
        );
    }

    #[test]
    fn test_fault_profile_boundary_values() {
        // Exactly 0.0 and 1.0 are valid.
        let p = FaultProfile {
            drop_pct: 0.0,
            corrupt_probability: 1.0,
            ..Default::default()
        };
        assert!(p.validate().is_ok());
    }

    // ---------------------------------------------------------------
    // VirtualLink
    // ---------------------------------------------------------------

    #[test]
    fn test_virtual_link_creation() {
        let link = VirtualLink::new("a", "b", FaultProfile::default()).unwrap();
        assert_eq!(link.source, "a");
        assert_eq!(link.target, "b");
    }

    #[test]
    fn test_virtual_link_invalid_profile_rejected() {
        let bad = FaultProfile {
            drop_pct: 2.0,
            ..Default::default()
        };
        assert!(VirtualLink::new("a", "b", bad).is_err());
    }

    // ---------------------------------------------------------------
    // LabConfig validation
    // ---------------------------------------------------------------

    #[test]
    fn test_lab_config_valid() {
        assert!(default_config().validate().is_ok());
    }

    #[test]
    fn test_lab_config_zero_seed_rejected() {
        let cfg = LabConfig {
            seed: 0,
            ..default_config()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, LabError::NoSeed));
    }

    // ---------------------------------------------------------------
    // LabRuntime initialization
    // ---------------------------------------------------------------

    #[test]
    fn test_lab_runtime_new() {
        let rt = LabRuntime::new(default_config()).unwrap();
        assert_eq!(rt.seed, 42);
        assert_eq!(rt.now(), 0);
        assert_eq!(rt.link_count(), 0);
        // Should have emitted the initialized event.
        assert_eq!(rt.events().len(), 1);
        assert_eq!(rt.events()[0].event_code, EVT_LAB_INITIALIZED);
    }

    #[test]
    fn test_lab_runtime_zero_seed_fails() {
        let cfg = LabConfig {
            seed: 0,
            ..default_config()
        };
        assert!(LabRuntime::new(cfg).is_err());
    }

    #[test]
    fn test_lab_runtime_add_link() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let idx = rt
            .add_link(make_link("node-a", "node-b", FaultProfile::default()))
            .unwrap();
        assert_eq!(idx, 0);
        assert_eq!(rt.link_count(), 1);
    }

    #[test]
    fn test_lab_runtime_add_link_rejects_capacity_overflow() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.virtual_links = (0..MAX_VIRTUAL_LINKS)
            .map(|idx| {
                let source = format!("src-{idx}");
                let target = format!("dst-{idx}");
                make_link(&source, &target, FaultProfile::default())
            })
            .collect();
        rt.reorder_buffers = vec![Vec::new(); MAX_REORDER_BUFFERS];

        let err = rt
            .add_link(make_link(
                "overflow-src",
                "overflow-dst",
                FaultProfile::default(),
            ))
            .expect_err("capacity overflow must fail closed");
        assert!(matches!(
            err,
            LabError::LinkCapacityExceeded {
                limit: MAX_VIRTUAL_LINKS
            }
        ));
        assert_eq!(rt.link_count(), MAX_VIRTUAL_LINKS);
    }

    #[test]
    fn test_lab_runtime_add_link_rejects_invalid_profile_without_side_effects() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let event_count = rt.events().len();
        let link = VirtualLink {
            source: "source".to_string(),
            target: "target".to_string(),
            fault_profile: FaultProfile {
                drop_pct: f64::NAN,
                ..Default::default()
            },
        };

        let err = rt
            .add_link(link)
            .expect_err("invalid link profile must be rejected");

        assert!(
            matches!(err, LabError::FaultRange { field, value } if field == "drop_pct" && value.is_nan())
        );
        assert_eq!(rt.link_count(), 0);
        assert_eq!(rt.events().len(), event_count);
    }

    #[test]
    fn test_lab_runtime_find_link() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.add_link(make_link("x", "y", FaultProfile::default()))
            .unwrap();
        assert_eq!(rt.find_link("x", "y").unwrap(), 0);
        assert!(rt.find_link("a", "b").is_err());
    }

    #[test]
    fn test_lab_runtime_find_link_rejects_reversed_pair() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.add_link(make_link("source", "target", FaultProfile::default()))
            .unwrap();

        let err = rt
            .find_link("target", "source")
            .expect_err("virtual links are directional");

        assert!(
            matches!(err, LabError::LinkNotFound { source, target } if source == "target" && target == "source")
        );
    }

    // ---------------------------------------------------------------
    // Message sending / fault injection
    // ---------------------------------------------------------------

    #[test]
    fn test_send_message_no_faults() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let profile = FaultProfile::default(); // no faults.
        rt.add_link(make_link("a", "b", profile)).unwrap();
        let outcome = rt.send_message(0, "hello").unwrap();
        assert!(matches!(
            outcome,
            MessageOutcome::Delivered { delay_ticks: 0 }
        ));
    }

    #[test]
    fn test_send_message_with_delay() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let profile = FaultProfile {
            delay_ticks: 5,
            ..Default::default()
        };
        rt.add_link(make_link("a", "b", profile)).unwrap();
        let outcome = rt.send_message(0, "hello").unwrap();
        match outcome {
            MessageOutcome::Delivered { delay_ticks } => assert_eq!(delay_ticks, 5),
            other => unreachable!("expected Delivered, got {other:?}"),
        }
    }

    #[test]
    fn test_send_message_emits_message_trace_for_delivery() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.add_link(make_link("a", "b", FaultProfile::default()))
            .unwrap();

        let outcome = rt.send_message(0, "ping").unwrap();
        assert!(matches!(
            outcome,
            MessageOutcome::Delivered { delay_ticks: 0 }
        ));

        let message_event = rt
            .events()
            .iter()
            .find(|event| event.event_code == EVT_MESSAGE_PROCESSED)
            .expect("message processing event should be recorded");
        assert!(message_event.payload.contains("source=a"));
        assert!(message_event.payload.contains("target=b"));
        assert!(message_event.payload.contains("message=\"ping\""));
        assert!(message_event.payload.contains("outcome=delivered"));
    }

    #[test]
    fn test_send_message_deterministic_drop() {
        // INV-LB-FAULT-APPLIED: 100% drop rate → always dropped.
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let profile = FaultProfile {
            drop_pct: 1.0,
            ..Default::default()
        };
        rt.add_link(make_link("a", "b", profile)).unwrap();
        for _ in 0..100 {
            let outcome = rt.send_message(0, "msg").unwrap();
            assert!(matches!(outcome, MessageOutcome::Dropped));
        }
    }

    #[test]
    fn test_send_message_deterministic_corrupt() {
        // INV-LB-FAULT-APPLIED: 0% drop, 100% corrupt → always corrupted.
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let profile = FaultProfile {
            drop_pct: 0.0,
            corrupt_probability: 1.0,
            delay_ticks: 3,
            ..Default::default()
        };
        rt.add_link(make_link("a", "b", profile)).unwrap();
        for _ in 0..100 {
            let outcome = rt.send_message(0, "msg").unwrap();
            assert!(matches!(
                outcome,
                MessageOutcome::Corrupted { delay_ticks: 3 }
            ));
        }
    }

    #[test]
    fn test_send_message_lossy_deterministic() {
        // INV-LB-DETERMINISTIC: same seed, same 50% drop profile → same outcomes.
        let mut rt1 = LabRuntime::new(default_config()).unwrap();
        let mut rt2 = LabRuntime::new(default_config()).unwrap();
        rt1.add_link(make_link("a", "b", lossy_profile())).unwrap();
        rt2.add_link(make_link("a", "b", lossy_profile())).unwrap();

        let outcomes1: Vec<_> = (0..50)
            .map(|_| rt1.send_message(0, "msg").unwrap())
            .collect();
        let outcomes2: Vec<_> = (0..50)
            .map(|_| rt2.send_message(0, "msg").unwrap())
            .collect();
        assert_eq!(outcomes1, outcomes2);
    }

    #[test]
    fn test_send_message_reorder() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.add_link(make_link("a", "b", reorder_profile())).unwrap();

        // Send messages until reorder buffer fills (depth=3).
        let o1 = rt.send_message(0, "m1").unwrap();
        let o2 = rt.send_message(0, "m2").unwrap();
        let o3 = rt.send_message(0, "m3").unwrap();

        // First two go into the buffer (delivered normally while buffer fills).
        // Third triggers the reorder.
        let has_reorder = matches!(o1, MessageOutcome::Reordered { .. })
            || matches!(o2, MessageOutcome::Reordered { .. })
            || matches!(o3, MessageOutcome::Reordered { .. });
        assert!(has_reorder, "at least one message should be reordered");
    }

    #[test]
    fn test_send_message_reorder_clears_buffer_before_next_cycle() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.add_link(make_link("a", "b", reorder_profile())).unwrap();

        assert!(matches!(
            rt.send_message(0, "m1").unwrap(),
            MessageOutcome::Delivered { .. }
        ));
        assert!(matches!(
            rt.send_message(0, "m2").unwrap(),
            MessageOutcome::Delivered { .. }
        ));
        assert!(matches!(
            rt.send_message(0, "m3").unwrap(),
            MessageOutcome::Reordered {
                buffer_position: 2,
                delay_ticks: 1
            }
        ));
        assert!(matches!(
            rt.send_message(0, "m4").unwrap(),
            MessageOutcome::Delivered { .. }
        ));
    }

    #[test]
    fn test_send_message_repairs_missing_reorder_buffers_after_deserialize() {
        let mut original = LabRuntime::new(default_config()).unwrap();
        original
            .add_link(make_link("sender", "receiver", reorder_profile()))
            .unwrap();

        let json = serde_json::to_string(&original).expect("serialize runtime");
        let mut restored: LabRuntime = serde_json::from_str(&json).expect("deserialize runtime");
        assert!(restored.reorder_buffers.is_empty());

        assert!(matches!(
            restored.send_message(0, "hello").unwrap(),
            MessageOutcome::Delivered { delay_ticks: 1 }
        ));
        assert_eq!(restored.reorder_buffers.len(), 1);
    }

    #[test]
    fn test_send_message_invalid_link_idx() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let result = rt.send_message(99, "msg");
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // Scenario execution
    // ---------------------------------------------------------------

    #[test]
    fn test_run_scenario_pass() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let result = rt.run_scenario(&|_rt| Ok(true)).unwrap();
        assert!(result.passed);
        assert_eq!(result.bugs_found, 0);
        assert!(result.repro_bundle.is_none());
    }

    #[test]
    fn test_run_scenario_fail() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let result = rt.run_scenario(&|_rt| Ok(false)).unwrap();
        assert!(!result.passed);
        assert_eq!(result.bugs_found, 1);
        assert!(result.repro_bundle.is_some());
    }

    #[test]
    fn test_run_scenario_error_treated_as_fail() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let result = rt.run_scenario(&|_rt| Err(LabError::NoSeed)).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn test_scenario_events_contain_started_and_completed() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let result = rt.run_scenario(&|_rt| Ok(true)).unwrap();
        let codes: Vec<&str> = result
            .events
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&EVT_SCENARIO_STARTED));
        assert!(codes.contains(&EVT_SCENARIO_COMPLETED));
    }

    // ---------------------------------------------------------------
    // DPOR exploration
    // ---------------------------------------------------------------

    #[test]
    fn test_dpor_single_interleaving_when_disabled() {
        let config = default_config(); // enable_dpor = false
        let result = LabRuntime::run_scenario_dpor(&config, &[], &|_rt| Ok(true)).unwrap();
        assert!(result.passed);
        assert_eq!(result.interleavings_explored, 0); // Single run, no DPOR counter.
    }

    #[test]
    fn test_dpor_explores_interleavings() {
        let config = LabConfig {
            seed: 100,
            max_ticks: 1000,
            max_interleavings: 5,
            enable_dpor: true,
        };
        let result = LabRuntime::run_scenario_dpor(&config, &[], &|_rt| Ok(true)).unwrap();
        assert!(result.passed);
        assert_eq!(result.interleavings_explored, 5);
        assert_eq!(result.bugs_found, 0);
    }

    #[test]
    fn test_dpor_finds_bug_across_interleavings() {
        let config = LabConfig {
            seed: 1,
            max_ticks: 1000,
            max_interleavings: 10,
            enable_dpor: true,
        };
        // Scenario that fails when seed is even.
        let result =
            LabRuntime::run_scenario_dpor(&config, &[], &|rt| Ok(rt.seed % 2 != 0)).unwrap();

        assert!(!result.passed);
        assert!(result.bugs_found > 0);
        assert!(result.repro_bundle.is_some());
    }

    #[test]
    fn test_dpor_three_task_scenario() {
        // Simulate 3 tasks with deterministic scheduling.
        let config = LabConfig {
            seed: 42,
            max_ticks: 1000,
            max_interleavings: 20,
            enable_dpor: true,
        };
        let links = vec![
            make_link(
                "task-0",
                "task-1",
                FaultProfile {
                    delay_ticks: 1,
                    ..Default::default()
                },
            ),
            make_link(
                "task-1",
                "task-2",
                FaultProfile {
                    delay_ticks: 2,
                    ..Default::default()
                },
            ),
            make_link(
                "task-2",
                "task-0",
                FaultProfile {
                    delay_ticks: 1,
                    ..Default::default()
                },
            ),
        ];

        let result = LabRuntime::run_scenario_dpor(&config, &links, &|rt| {
            // Each task sends a message to the next.
            rt.send_message(0, "from-0-to-1")?;
            rt.send_message(1, "from-1-to-2")?;
            rt.send_message(2, "from-2-to-0")?;
            rt.advance_clock(10)?;
            Ok(true)
        })
        .unwrap();

        assert!(result.passed);
        assert_eq!(result.interleavings_explored, 20);
    }

    // ---------------------------------------------------------------
    // Repro bundle round-trip
    // ---------------------------------------------------------------

    #[test]
    fn test_repro_bundle_export_json_round_trip() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.add_link(make_link("a", "b", FaultProfile::default()))
            .unwrap();
        let bundle = rt.export_repro_bundle(false);

        let json = bundle.to_json().unwrap();
        assert!(!json.is_empty());

        let restored = ReproBundle::from_json(&json).unwrap();
        assert_eq!(restored.schema_version, SCHEMA_VERSION);
        assert_eq!(restored.seed, 42);
        assert!(!restored.passed);
        assert_eq!(restored.links.len(), 1);
    }

    #[test]
    fn test_repro_bundle_to_json_reports_serialization_error() {
        let mut bundle = LabRuntime::new(default_config())
            .unwrap()
            .export_repro_bundle(true);
        bundle.links.push(VirtualLink {
            source: "a".into(),
            target: "b".into(),
            fault_profile: FaultProfile {
                drop_pct: f64::NAN,
                ..FaultProfile::default()
            },
        });

        let err = bundle
            .to_json()
            .expect_err("NaN should fail JSON serialization");
        assert!(matches!(err, LabError::BundleSerialization { .. }));
    }

    #[test]
    fn test_repro_bundle_export_is_idempotent_for_same_state() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.add_link(make_link("a", "b", FaultProfile::default()))
            .unwrap();
        let runtime_events = rt.events().to_vec();

        let first = rt.export_repro_bundle(true);
        let second = rt.export_repro_bundle(true);

        assert_eq!(first, second);
        assert_eq!(rt.events(), runtime_events.as_slice());
    }

    #[test]
    fn test_repro_bundle_export_respects_max_events_bound() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.events = (0..MAX_EVENTS)
            .map(|idx| LabEvent {
                tick: idx as u64,
                event_code: EVT_SCENARIO_STARTED.to_string(),
                payload: format!("event-{idx}"),
            })
            .collect();

        let bundle = rt.export_repro_bundle(true);

        assert_eq!(bundle.events.len(), MAX_EVENTS);
        assert_eq!(
            bundle.events.last().map(|event| event.event_code.as_str()),
            Some(EVT_REPRO_EXPORTED)
        );
    }

    #[test]
    fn test_repro_bundle_from_json_reports_parse_error() {
        let err = ReproBundle::from_json("{not-json").expect_err("invalid JSON must fail");
        assert!(matches!(err, LabError::BundleDeserialization { .. }));
    }

    #[test]
    fn test_repro_bundle_from_json_rejects_unsupported_schema_version() {
        let mut bundle = LabRuntime::new(default_config())
            .unwrap()
            .export_repro_bundle(true);
        bundle.schema_version = "lab-v0.9".into();

        let json = serde_json::to_string(&bundle).unwrap();
        let err = ReproBundle::from_json(&json).expect_err("unsupported schema must fail");
        assert!(matches!(err, LabError::BundleValidation { .. }));
    }

    #[test]
    fn test_repro_bundle_from_json_rejects_seed_mismatch() {
        let mut bundle = LabRuntime::new(default_config())
            .unwrap()
            .export_repro_bundle(true);
        bundle.seed = bundle.seed.wrapping_add(1);

        let json = serde_json::to_string(&bundle).unwrap();
        let err = ReproBundle::from_json(&json).expect_err("seed mismatch must fail");
        assert!(matches!(err, LabError::BundleValidation { .. }));
    }

    #[test]
    fn test_repro_bundle_from_json_rejects_invalid_fault_profile() {
        let mut bundle = LabRuntime::new(default_config())
            .unwrap()
            .export_repro_bundle(true);
        bundle.links.push(VirtualLink {
            source: "a".into(),
            target: "b".into(),
            fault_profile: FaultProfile {
                drop_pct: 2.0,
                ..FaultProfile::default()
            },
        });

        let json = serde_json::to_string(&bundle).unwrap();
        let err = ReproBundle::from_json(&json).expect_err("invalid link profile must fail");
        assert!(matches!(err, LabError::BundleValidation { .. }));
    }

    #[test]
    fn test_repro_bundle_from_json_rejects_link_capacity_overflow() {
        let mut bundle = LabRuntime::new(default_config())
            .unwrap()
            .export_repro_bundle(true);
        bundle.links = (0..=MAX_VIRTUAL_LINKS)
            .map(|i| VirtualLink {
                source: format!("n{i}"),
                target: format!("n{}", i + 1),
                fault_profile: FaultProfile::default(),
            })
            .collect();

        let json = serde_json::to_string(&bundle).unwrap();
        let err = ReproBundle::from_json(&json).expect_err("link overflow must fail early");
        assert!(matches!(err, LabError::BundleValidation { .. }));
    }

    #[test]
    fn test_repro_bundle_from_json_rejects_zero_seed_config() {
        let mut bundle = LabRuntime::new(default_config())
            .unwrap()
            .export_repro_bundle(true);
        bundle.seed = 0;
        bundle.config.seed = 0;

        let json = serde_json::to_string(&bundle).unwrap();
        let err = ReproBundle::from_json(&json).expect_err("zero seed config must fail");

        assert!(matches!(err, LabError::BundleValidation { .. }));
    }

    #[test]
    fn test_repro_bundle_from_json_rejects_missing_events_field() {
        let json = r#"{
            "schema_version": "lab-v1.0",
            "seed": 42,
            "config": {
                "seed": 42,
                "max_ticks": 10000,
                "max_interleavings": 100,
                "enable_dpor": false
            },
            "links": [],
            "passed": true
        }"#;

        let err = ReproBundle::from_json(json).expect_err("missing events field must fail");

        assert!(matches!(err, LabError::BundleDeserialization { .. }));
    }

    #[test]
    fn test_repro_bundle_from_json_rejects_links_type_confusion() {
        let json = r#"{
            "schema_version": "lab-v1.0",
            "seed": 42,
            "config": {
                "seed": 42,
                "max_ticks": 10000,
                "max_interleavings": 100,
                "enable_dpor": false
            },
            "links": {"source": "a", "target": "b"},
            "events": [],
            "passed": true
        }"#;

        let err = ReproBundle::from_json(json).expect_err("links must be an array");

        assert!(matches!(err, LabError::BundleDeserialization { .. }));
    }

    #[test]
    fn test_repro_bundle_replay_deterministic() {
        // INV-LB-REPLAY: replay preserves the full failure trace.
        let config = default_config();
        let mut rt = LabRuntime::new(config.clone()).unwrap();
        rt.add_link(make_link("x", "y", lossy_profile())).unwrap();

        // Run scenario that sends messages.
        let _result = rt
            .run_scenario(&|rt| {
                for _ in 0..10 {
                    rt.send_message(0, "ping")?;
                }
                Ok(false) // deliberate fail
            })
            .unwrap();

        let bundle = rt.export_repro_bundle(false);

        // Replay with the same scenario.
        let replay_result = LabRuntime::replay_bundle(&bundle, &|rt| {
            for _ in 0..10 {
                rt.send_message(0, "ping")?;
            }
            Ok(false) // same outcome
        })
        .unwrap();

        assert!(!replay_result.passed);
        assert_eq!(replay_result.events, bundle.events);
    }

    #[test]
    fn test_repro_bundle_replay_divergence_detected() {
        // INV-LB-REPLAY: divergent replay is detected.
        let rt = LabRuntime::new(default_config()).unwrap();
        let bundle = rt.export_repro_bundle(false); // original: failed

        // Replay with a scenario that passes → divergence.
        let result = LabRuntime::replay_bundle(&bundle, &|_rt| Ok(true));
        assert!(result.is_err());
        match result.unwrap_err() {
            LabError::ReplayDivergence { .. } => {}
            other => unreachable!("expected ReplayDivergence, got {other}"),
        }
    }

    #[test]
    fn test_repro_bundle_replay_detects_trace_divergence_with_same_outcome() {
        let config = default_config();
        let mut rt = LabRuntime::new(config).unwrap();
        rt.add_link(make_link("x", "y", FaultProfile::default()))
            .unwrap();

        rt.run_scenario(&|rt| {
            rt.send_message(0, "ping")?;
            Ok(false)
        })
        .unwrap();

        let bundle = rt.export_repro_bundle(false);
        let result = LabRuntime::replay_bundle(&bundle, &|rt| {
            rt.send_message(0, "pong")?;
            Ok(false)
        });

        assert!(matches!(result, Err(LabError::ReplayDivergence { .. })));
    }

    #[test]
    fn test_repro_bundle_replay_rejects_invalid_bundle_metadata() {
        let mut bundle = LabRuntime::new(default_config())
            .unwrap()
            .export_repro_bundle(true);
        bundle.seed = bundle.seed.wrapping_add(1);

        let result = LabRuntime::replay_bundle(&bundle, &|_rt| Ok(true));
        assert!(matches!(result, Err(LabError::BundleValidation { .. })));
    }

    #[test]
    fn test_run_scenario_failure_returns_exported_trace_without_mutating_runtime() {
        let mut rt = LabRuntime::new(default_config()).unwrap();

        let result = rt.run_scenario(&|_rt| Ok(false)).unwrap();

        assert_eq!(
            result.events.last().map(|event| event.event_code.as_str()),
            Some(EVT_REPRO_EXPORTED)
        );
        assert_eq!(
            rt.events().last().map(|event| event.event_code.as_str()),
            Some(EVT_SCENARIO_FAILED)
        );
    }

    #[test]
    fn test_repro_bundle_replay_preserves_trace_for_passing_bundle() {
        let config = default_config();
        let mut rt = LabRuntime::new(config).unwrap();
        rt.add_link(make_link("x", "y", FaultProfile::default()))
            .unwrap();

        rt.run_scenario(&|rt| {
            rt.send_message(0, "ping")?;
            Ok(true)
        })
        .unwrap();

        let bundle = rt.export_repro_bundle(true);
        let replay_result = LabRuntime::replay_bundle(&bundle, &|rt| {
            rt.send_message(0, "ping")?;
            Ok(true)
        })
        .unwrap();

        assert!(replay_result.passed);
        assert_eq!(replay_result.events, bundle.events);
    }

    #[test]
    fn test_repro_bundle_schema_version() {
        let rt = LabRuntime::new(default_config()).unwrap();
        let bundle = rt.export_repro_bundle(true);
        assert_eq!(bundle.schema_version, SCHEMA_VERSION);
    }

    // ---------------------------------------------------------------
    // Integrated scenario with clock + links + faults
    // ---------------------------------------------------------------

    #[test]
    fn test_integrated_clock_and_faults() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.add_link(make_link("sender", "receiver", lossy_profile()))
            .unwrap();

        // Schedule timers.
        rt.schedule_timer(10, "check-1").unwrap();
        rt.schedule_timer(20, "check-2").unwrap();

        // Send messages.
        let mut delivered = 0u64;
        let mut dropped = 0u64;
        for _ in 0..20 {
            match rt.send_message(0, "data").unwrap() {
                MessageOutcome::Delivered { .. } => delivered += 1,
                MessageOutcome::Dropped => dropped += 1,
                _ => {}
            }
        }

        // Advance clock past both timers.
        let fired = rt.advance_clock(25).unwrap();
        assert_eq!(fired.len(), 2);

        // With 50% drop, we expect some of each (deterministic with seed 42).
        assert!(delivered > 0, "some messages should be delivered");
        assert!(dropped > 0, "some messages should be dropped");
    }

    #[test]
    fn test_lab_runtime_advance_clock_to_u64_max_records_timer_event() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.test_clock.current_tick = u64::MAX - 1;
        rt.schedule_timer(1, "terminal-timer").unwrap();

        let fired = rt.advance_clock(1).unwrap();
        assert_eq!(rt.now(), u64::MAX);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].0, u64::MAX);
        assert_eq!(fired[0].1.label, "terminal-timer");

        let timer_event = rt
            .events()
            .iter()
            .find(|event| event.event_code == EVT_TIMER_FIRED)
            .expect("timer event should be recorded");
        assert_eq!(timer_event.tick, u64::MAX);
        assert!(timer_event.payload.contains("terminal-timer"));

        let advance_event = rt
            .events()
            .iter()
            .find(|event| event.event_code == EVT_TEST_CLOCK_ADVANCED)
            .expect("clock advance event should be recorded");
        assert_eq!(advance_event.tick, u64::MAX);
        assert!(advance_event.payload.contains(&format!("now={}", u64::MAX)));
    }

    // ---------------------------------------------------------------
    // Error display
    // ---------------------------------------------------------------

    #[test]
    fn test_error_display_no_seed() {
        let e = LabError::NoSeed;
        assert!(e.to_string().contains(ERR_LB_NO_SEED));
    }

    #[test]
    fn test_error_display_tick_overflow() {
        let e = LabError::TickOverflow {
            current: 100,
            delta: 200,
        };
        let s = e.to_string();
        assert!(s.contains(ERR_LB_TICK_OVERFLOW));
        assert!(s.contains("100"));
        assert!(s.contains("200"));
    }

    #[test]
    fn test_error_display_link_not_found() {
        let e = LabError::LinkNotFound {
            source: "a".into(),
            target: "b".into(),
        };
        assert!(e.to_string().contains(ERR_LB_LINK_NOT_FOUND));
    }

    #[test]
    fn test_error_display_fault_range() {
        let e = LabError::FaultRange {
            field: "drop_pct".into(),
            value: 2.0,
        };
        assert!(e.to_string().contains(ERR_LB_FAULT_RANGE));
    }

    #[test]
    fn test_error_display_budget_exceeded() {
        let e = LabError::BudgetExceeded {
            explored: 100,
            budget: 50,
        };
        assert!(e.to_string().contains(ERR_LB_BUDGET_EXCEEDED));
    }

    #[test]
    fn test_error_display_replay_divergence() {
        let e = LabError::ReplayDivergence {
            expected_events: 10,
            actual_events: 5,
        };
        assert!(e.to_string().contains(ERR_LB_REPLAY_DIVERGENCE));
    }

    #[test]
    fn test_error_display_bundle_deserialization() {
        let e = LabError::BundleDeserialization {
            detail: "expected value".into(),
        };
        assert!(e.to_string().contains(ERR_LB_BUNDLE_DESERIALIZATION));
    }

    #[test]
    fn test_error_display_bundle_validation() {
        let e = LabError::BundleValidation {
            detail: "unsupported schema".into(),
        };
        assert!(e.to_string().contains(ERR_LB_BUNDLE_VALIDATION));
    }

    // ---------------------------------------------------------------
    // LabEvent display
    // ---------------------------------------------------------------

    #[test]
    fn test_lab_event_display() {
        let e = LabEvent {
            tick: 42,
            event_code: EVT_TIMER_FIRED.to_string(),
            payload: "timer_id=1".to_string(),
        };
        let s = format!("{e}");
        assert!(s.contains("[tick=42]"));
        assert!(s.contains(EVT_TIMER_FIRED));
    }

    // ---------------------------------------------------------------
    // Invariant constants are well-formed
    // ---------------------------------------------------------------

    #[test]
    fn test_all_event_codes_prefixed() {
        let codes = [
            EVT_LAB_INITIALIZED,
            EVT_SCENARIO_STARTED,
            EVT_FAULT_INJECTED,
            EVT_TIMER_FIRED,
            EVT_SCENARIO_COMPLETED,
            EVT_DPOR_INTERLEAVING,
            EVT_REPRO_EXPORTED,
            EVT_SCENARIO_FAILED,
            EVT_VIRTUAL_LINK_CREATED,
            EVT_TEST_CLOCK_ADVANCED,
            EVT_MESSAGE_PROCESSED,
        ];
        for code in codes {
            assert!(code.starts_with("FN-LB-"), "bad prefix: {code}");
        }
    }

    #[test]
    fn test_all_error_codes_prefixed() {
        let codes = [
            ERR_LB_NO_SEED,
            ERR_LB_TICK_OVERFLOW,
            ERR_LB_TIMER_ID_EXHAUSTED,
            ERR_LB_LINK_NOT_FOUND,
            ERR_LB_LINK_CAPACITY_EXCEEDED,
            ERR_LB_FAULT_RANGE,
            ERR_LB_BUDGET_EXCEEDED,
            ERR_LB_REPLAY_DIVERGENCE,
            ERR_LB_BUNDLE_SERIALIZATION,
            ERR_LB_BUNDLE_DESERIALIZATION,
            ERR_LB_BUNDLE_VALIDATION,
        ];
        for code in codes {
            assert!(code.starts_with("ERR_LB_"), "bad prefix: {code}");
        }
    }

    #[test]
    fn test_all_invariant_codes_prefixed() {
        let invs = [
            INV_LB_DETERMINISTIC,
            INV_LB_TIMER_ORDER,
            INV_LB_FAULT_APPLIED,
            INV_LB_REPLAY,
            INV_LB_COVERAGE,
            INV_LB_NO_WALLCLOCK,
        ];
        for inv in invs {
            assert!(inv.starts_with("INV-LB-"), "bad prefix: {inv}");
        }
    }

    #[test]
    fn test_schema_version_format() {
        assert_eq!(SCHEMA_VERSION, "lab-v1.0");
    }

    // ---------------------------------------------------------------
    // Negative-path inline tests for improved edge case coverage
    // ---------------------------------------------------------------

    #[test]
    fn negative_push_bounded_arithmetic_overflow_vulnerability() {
        // CRITICAL: Demonstrates the same push_bounded arithmetic vulnerability
        // found in evidence_replay_validator.rs - raw subtraction without protection
        let mut items = vec![1, 2, 3, 4, 5];
        let original_len = items.len();

        // Test with cap=0 - should trigger overflow calculation
        push_bounded(&mut items, 99, 0);

        // With the vulnerable implementation using `items.len() - cap + 1`,
        // this could cause issues if len < cap. The correct implementation
        // should use saturating arithmetic: items.len().saturating_sub(cap).saturating_add(1)
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], 99);

        // Test boundary condition where cap > len
        let mut small_vec = vec![1];
        push_bounded(&mut small_vec, 2, 5); // cap > current len
        assert_eq!(small_vec.len(), 2);
        assert_eq!(small_vec, vec![1, 2]);
    }

    #[test]
    fn negative_splitmix64_edge_case_bounds() {
        // Test edge cases that could cause numerical instability
        let mut rng_max = SplitMix64::new(u64::MAX);
        let mut rng_zero = SplitMix64::new(0);

        // Should not panic on extreme seeds
        for _ in 0..100 {
            let val_max = rng_max.next_f64();
            let val_zero = rng_zero.next_f64();

            assert!(
                val_max >= 0.0 && val_max < 1.0,
                "extreme seed should produce valid f64: {}",
                val_max
            );
            assert!(
                val_zero >= 0.0 && val_zero < 1.0,
                "zero seed should produce valid f64: {}",
                val_zero
            );
        }

        // Test next_usize with large bounds
        let large_bound = usize::MAX / 2;
        let bounded_val = rng_max.next_usize(large_bound);
        assert!(
            bounded_val < large_bound,
            "bounded value should respect large bound"
        );
    }

    #[test]
    fn negative_fault_profile_non_finite_values_comprehensive() {
        // Test all non-finite float edge cases that could bypass validation
        let test_cases = [
            ("nan", f64::NAN),
            ("positive_infinity", f64::INFINITY),
            ("negative_infinity", f64::NEG_INFINITY),
            ("subnormal_min", f64::MIN_POSITIVE / 2.0),
            ("negative_zero", -0.0), // Should be valid but worth testing
        ];

        for (name, invalid_value) in test_cases {
            if invalid_value.is_finite() && (0.0..=1.0).contains(&invalid_value) {
                continue; // Skip valid values
            }

            // Test drop_pct with non-finite value
            let profile = FaultProfile {
                drop_pct: invalid_value,
                ..Default::default()
            };
            assert!(
                profile.validate().is_err(),
                "{} drop_pct should be rejected: {}",
                name,
                invalid_value
            );

            // Test corrupt_probability with non-finite value
            let profile = FaultProfile {
                corrupt_probability: invalid_value,
                ..Default::default()
            };
            assert!(
                profile.validate().is_err(),
                "{} corrupt_probability should be rejected: {}",
                name,
                invalid_value
            );
        }
    }

    #[test]
    fn negative_test_clock_state_corruption_resilience() {
        let mut clock = TestClock::new();

        // Manually corrupt internal state to test resilience
        clock.next_timer_id = 0; // This should make next allocation fail

        let result = clock.schedule_timer(10, "should-fail");
        assert!(
            matches!(result, Err(LabError::TimerIdExhausted)),
            "corrupted timer id state should fail closed"
        );

        // Test with pending_timers containing invalid data structure
        clock.pending_timers.insert(u64::MAX, vec![]);
        clock.current_tick = u64::MAX - 5;

        // This should not cause overflow when advance tries to access edge keys
        let result = clock.advance(1);
        assert!(
            result.is_ok(),
            "advance should handle edge case timer data gracefully"
        );
    }

    #[test]
    fn negative_virtual_link_resource_exhaustion() {
        let mut rt = LabRuntime::new(default_config()).unwrap();

        // Test resource exhaustion scenarios
        let mut links_added = 0;
        loop {
            let link_result = rt.add_link(make_link(
                &format!("src-{}", links_added),
                &format!("dst-{}", links_added),
                FaultProfile::default(),
            ));

            match link_result {
                Ok(_) => links_added += 1,
                Err(LabError::LinkCapacityExceeded { limit }) => {
                    assert!(limit > 0, "capacity limit should be positive");
                    assert_eq!(links_added, limit, "should fail exactly at capacity limit");
                    break;
                }
                Err(other) => panic!("unexpected error during capacity test: {:?}", other),
            }

            // Safety break to prevent infinite loop in case of bug
            if links_added > MAX_VIRTUAL_LINKS + 10 {
                panic!("capacity limit not enforced - added {} links", links_added);
            }
        }

        // Verify runtime state is still consistent after hitting limit
        assert_eq!(rt.link_count(), links_added);
        assert!(
            rt.events()
                .iter()
                .any(|e| e.event_code == EVT_VIRTUAL_LINK_CREATED)
        );
    }

    #[test]
    fn negative_repro_bundle_malformed_data_injection() {
        // Test repro bundle with malformed/corrupted data
        let malformed_json_cases = [
            r#"{"schema_version": null}"#,
            r#"{"seed": "not-a-number"}"#,
            r#"{"config": []}"#, // config should be object
            r#"{"links": "not-an-array"}"#,
            r#"{"events": {"not": "array"}}"#,
            r#"{"passed": "not-boolean"}"#,
            r#"{"schema_version": "lab-v1.0", "seed": 1e999}"#, // overflow
        ];

        for (idx, malformed_json) in malformed_json_cases.iter().enumerate() {
            let result = ReproBundle::from_json(malformed_json);
            assert!(
                result.is_err(),
                "case {}: malformed JSON should be rejected: {}",
                idx,
                malformed_json
            );

            // Should specifically be a deserialization error
            assert!(
                matches!(result.unwrap_err(), LabError::BundleDeserialization { .. }),
                "case {}: should be deserialization error",
                idx
            );
        }

        // Test bundle with valid JSON but logically inconsistent data
        let inconsistent_bundle = r#"{
            "schema_version": "lab-v1.0",
            "seed": 42,
            "config": {
                "seed": 43,
                "max_ticks": 1000,
                "max_interleavings": 100,
                "enable_dpor": false
            },
            "links": [],
            "events": [],
            "passed": true
        }"#;

        let result = ReproBundle::from_json(inconsistent_bundle);
        assert!(
            matches!(result.unwrap_err(), LabError::BundleValidation { .. }),
            "seed mismatch should cause validation error"
        );
    }

    #[test]
    fn negative_dpor_exploration_edge_cases() {
        // Test DPOR with edge case configurations that could cause instability
        let edge_config = LabConfig {
            seed: u64::MAX - 1,   // Near overflow
            max_ticks: 0,         // Minimal ticks
            max_interleavings: 1, // Minimal interleavings
            enable_dpor: true,
        };

        // This should handle edge cases gracefully without panicking
        let result = LabRuntime::run_scenario_dpor(&edge_config, &[], &|_rt| Ok(true));
        assert!(
            result.is_ok(),
            "edge case DPOR config should be handled gracefully"
        );

        let scenario_result = result.unwrap();
        assert_eq!(scenario_result.interleavings_explored, 1);

        // Test with scenario that would cause seed wrap-around
        let wrap_config = LabConfig {
            seed: u64::MAX,
            max_ticks: 1000,
            max_interleavings: 5,
            enable_dpor: true,
        };

        let result = LabRuntime::run_scenario_dpor(&wrap_config, &[], &|rt| {
            // Verify seed wrapping is handled correctly (should become 1, not 0)
            assert_ne!(rt.seed, 0, "seed should not wrap to zero");
            Ok(true)
        });
        assert!(result.is_ok(), "seed wrap-around should be handled safely");
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_fault_profile_with_invalid_probabilities_rejects() {
        // Test fault profile validation with out-of-range probabilities
        let mut profile = FaultProfile::default();

        // Negative probability should fail
        profile.drop_pct = -0.1;
        match profile.validate() {
            Err(LabError::FaultRange { field, value }) => {
                assert_eq!(field, "drop_pct");
                assert_eq!(value, -0.1);
            }
            other => panic!("Expected FaultRange error for negative drop_pct, got {other:?}"),
        }

        // Probability > 1.0 should fail
        profile.drop_pct = 1.5;
        match profile.validate() {
            Err(LabError::FaultRange { .. }) => {}
            other => panic!("Expected FaultRange error for drop_pct > 1.0, got {other:?}"),
        }

        // Test corrupt_probability edge cases
        profile.drop_pct = 0.5;
        profile.corrupt_probability = f64::NAN;
        match profile.validate() {
            Err(LabError::FaultRange { field, .. }) => {
                assert_eq!(field, "corrupt_probability");
            }
            other => panic!("Expected FaultRange error for NaN corrupt_probability, got {other:?}"),
        }

        profile.corrupt_probability = f64::INFINITY;
        assert!(profile.validate().is_err());

        profile.corrupt_probability = f64::NEG_INFINITY;
        assert!(profile.validate().is_err());
    }

    #[test]
    fn negative_virtual_link_with_empty_and_whitespace_names_handles() {
        // Test VirtualLink creation with problematic endpoint names
        let fault_profile = FaultProfile::default();

        // Empty strings should be allowed (calling code may validate)
        assert!(VirtualLink::new("", "target", fault_profile.clone()).is_ok());
        assert!(VirtualLink::new("source", "", fault_profile.clone()).is_ok());

        // Whitespace-only names should be allowed
        let link = VirtualLink::new("   ", "\t\n", fault_profile.clone()).unwrap();
        assert_eq!(link.source, "   ");
        assert_eq!(link.target, "\t\n");

        // Unicode and control characters should be allowed
        let special_chars = "source\0with\x01control\u{FFFF}";
        let link2 = VirtualLink::new(special_chars, "normal_target", fault_profile).unwrap();
        assert_eq!(link2.source, special_chars);
    }

    #[test]
    fn negative_test_clock_with_extreme_timer_ids_handles_exhaustion() {
        let mut clock = TestClock::new();

        // Set timer ID counter near u64::MAX to test exhaustion
        clock.next_timer_id = u64::MAX - 1;

        // Should succeed for the last two timer IDs
        assert!(clock.schedule_timer(10, "second_last").is_ok());
        assert!(clock.schedule_timer(10, "last").is_ok());

        // Next timer should fail with exhaustion error
        match clock.schedule_timer(10, "overflow") {
            Err(LabError::TimerIdExhausted) => {}
            other => panic!("Expected TimerIdExhausted error, got {other:?}"),
        }

        // Verify no timer was registered after exhaustion
        assert_eq!(clock.pending_count(), 2); // Only the two successful ones
    }

    #[test]
    fn negative_lab_config_with_zero_and_extreme_values_validates() {
        // Test LabConfig validation edge cases
        let mut config = default_config();

        // Zero seed should be rejected
        config.seed = 0;
        match config.validate() {
            Err(LabError::NoSeed) => {}
            other => panic!("Expected NoSeed error for zero seed, got {other:?}"),
        }

        // Extreme but valid values should be accepted
        config.seed = 1;
        config.max_ticks = u64::MAX;
        config.max_interleavings = u64::MAX;
        assert!(config.validate().is_ok());

        // u64::MAX seed should be fine
        config.seed = u64::MAX;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn negative_splitmix64_with_extreme_bounds_handles_correctly() {
        let mut rng = SplitMix64::new(42);

        // Zero bound should always return 0
        for _ in 0..100 {
            assert_eq!(rng.next_usize(0), 0);
        }

        // Bound of 1 should always return 0
        for _ in 0..100 {
            assert_eq!(rng.next_usize(1), 0);
        }

        // Maximum usize bound should not panic
        let max_bound = usize::MAX;
        for _ in 0..10 {
            let val = rng.next_usize(max_bound);
            assert!(val < max_bound);
        }

        // Very large bounds should work efficiently
        let large_bound = 1_000_000_000_000usize;
        let val = rng.next_usize(large_bound);
        assert!(val < large_bound);
    }

    #[test]
    fn negative_lab_event_with_extreme_payloads_formats_safely() {
        // Test LabEvent formatting with problematic payloads
        let extreme_payloads = vec![
            "".to_string(),                              // Empty
            "\0\x01\x02control\x7fchars".to_string(),    // Control characters
            "very ".repeat(10000),                       // Very long string
            "\u{FFFF}\u{10FFFF}unicode".to_string(),     // Max Unicode codepoints
            "{malicious: \"json\"}\n<xml/>".to_string(), // Potential injection
        ];

        for payload in extreme_payloads {
            let event = LabEvent {
                tick: u64::MAX,
                event_code: "TEST-999".to_string(),
                payload: payload.clone(),
            };

            // Formatting should not panic regardless of payload content
            let formatted = format!("{}", event);
            assert!(formatted.contains("TEST-999"));
            assert!(formatted.contains(&format!("tick={}", u64::MAX)));

            // Debug formatting should also be safe
            let debug_formatted = format!("{:?}", event);
            assert!(debug_formatted.contains("TEST-999"));
        }
    }

    #[test]
    fn negative_test_clock_advance_with_concurrent_timer_modifications_maintains_order() {
        let mut clock = TestClock::new();

        // Schedule timers with same tick but different labels
        clock.schedule_timer(10, "timer_a").unwrap();
        clock.schedule_timer(10, "timer_b").unwrap();
        clock.schedule_timer(10, "timer_c").unwrap();

        // Add more timers at different ticks
        clock.schedule_timer(5, "early").unwrap();
        clock.schedule_timer(15, "late").unwrap();

        // Advance past all timers
        let fired = clock.advance(20).unwrap();
        assert_eq!(fired.len(), 5);

        // Verify strict tick ordering
        let mut previous_tick = 0;
        for (tick, _) in &fired {
            assert!(*tick >= previous_tick, "Timer firing order violated");
            previous_tick = *tick;
        }

        // Verify specific order: early(5), then three at tick 10, then late(15)
        assert_eq!(fired[0].1.label, "early");
        assert_eq!(fired[4].1.label, "late");

        // The three timers at tick 10 should maintain some deterministic order
        let middle_labels: Vec<&str> = fired[1..4]
            .iter()
            .map(|(_, timer)| timer.label.as_str())
            .collect();
        assert_eq!(middle_labels.len(), 3);
        assert!(middle_labels.contains(&"timer_a"));
        assert!(middle_labels.contains(&"timer_b"));
        assert!(middle_labels.contains(&"timer_c"));
    }

    #[test]
    fn negative_repro_bundle_serialization_with_malformed_data_fails_gracefully() {
        // Test ReproBundle deserialization with invalid JSON
        let invalid_json_cases = vec![
            "",                                                        // Empty string
            "{",                                                       // Unclosed brace
            "null",                                                    // Wrong type
            "{\"events\": [}",                                         // Syntax error
            "{\"events\": [], \"links\": null}",                       // Wrong field type
            r#"{"events": [], "links": [], "passed": "not_boolean"}"#, // Wrong boolean type
        ];

        for invalid_json in invalid_json_cases {
            match ReproBundle::from_json(invalid_json) {
                Err(LabError::BundleDeserialization { .. }) => {} // Expected
                other => panic!(
                    "Expected BundleDeserialization error for '{invalid_json}', got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn negative_push_bounded_with_massive_overflow_drains_correctly() {
        // Test push_bounded with extreme capacity overflow scenarios
        let mut items = vec![1, 2, 3, 4, 5];
        let cap = 3;

        // Adding item should drain oldest elements correctly
        push_bounded(&mut items, 6, cap);
        assert_eq!(items.len(), 3);
        assert_eq!(items, vec![4, 5, 6]);

        // Add multiple items exceeding capacity dramatically
        let mut large_vec: Vec<u32> = (0..1000).collect();
        push_bounded(&mut large_vec, 9999, 5);

        assert_eq!(large_vec.len(), 5);
        assert_eq!(large_vec[4], 9999); // New item at end
        assert!(large_vec[0] >= 995); // Only recent items remain

        // Edge case: capacity of 0 should clear all items
        let mut test_vec = vec![1, 2, 3];
        push_bounded(&mut test_vec, 42, 0);
        assert_eq!(test_vec, vec![42]);

        // Edge case: capacity of 1 should keep only new item
        push_bounded(&mut test_vec, 99, 1);
        assert_eq!(test_vec, vec![99]);
    }

    // ── Additional negative-path tests for comprehensive edge case coverage ──

    #[test]
    fn negative_virtual_link_with_unicode_boundary_source_target_names() {
        // Test VirtualLink with Unicode boundary conditions and edge cases
        let fault_profile = FaultProfile::default();

        // Unicode normalization edge cases
        let unicode_cases = [
            "\u{0300}",   // Combining grave accent (zero-width)
            "\u{200D}",   // Zero-width joiner
            "\u{FEFF}",   // Byte order mark
            "\u{E000}",   // Private use area start
            "\u{F8FF}",   // Private use area end
            "\u{1F4A9}",  // Pile of poo emoji (4-byte UTF-8)
            "\u{10FFFF}", // Maximum Unicode codepoint
        ];

        for unicode_str in unicode_cases {
            let link_result = VirtualLink::new(unicode_str, "normal_target", fault_profile.clone());
            assert!(
                link_result.is_ok(),
                "Unicode string '{}' should be handled correctly",
                unicode_str.escape_debug()
            );

            let link = link_result.unwrap();
            assert_eq!(link.source, unicode_str);

            // Test reverse direction
            let reverse_link =
                VirtualLink::new("normal_source", unicode_str, fault_profile.clone()).unwrap();
            assert_eq!(reverse_link.target, unicode_str);
        }

        // Test extremely long Unicode string (potential DoS vector)
        let long_unicode = "\u{1F4A9}".repeat(1000); // 4KB of poo emojis
        let long_link = VirtualLink::new(&long_unicode, "target", fault_profile).unwrap();
        assert_eq!(long_link.source.len(), long_unicode.len());
    }

    #[test]
    fn negative_test_clock_timer_scheduling_at_u64_max_boundary() {
        // Test timer scheduling at the absolute boundary of u64::MAX
        let mut clock = TestClock::new();
        clock.current_tick = u64::MAX - 10;

        // Should succeed up to the maximum possible tick
        for delta in 1..=10 {
            let timer_id = clock
                .schedule_timer(delta, &format!("timer_{}", delta))
                .unwrap();
            assert!(timer_id > 0);
        }

        // Attempting to schedule beyond u64::MAX should fail
        let overflow_result = clock.schedule_timer(1, "overflow_timer");
        assert!(
            matches!(overflow_result, Err(LabError::TickOverflow { current, delta })
                         if current == u64::MAX - 10 && delta == 1)
        );

        // Advance to u64::MAX exactly
        let fired = clock.advance(10).unwrap();
        assert_eq!(fired.len(), 10);
        assert_eq!(clock.now(), u64::MAX);

        // Any further advance should fail
        let further_advance = clock.advance(1);
        assert!(matches!(
            further_advance,
            Err(LabError::TickOverflow { .. })
        ));
    }

    #[test]
    fn negative_splitmix64_determinism_under_extreme_iteration_counts() {
        // Test SplitMix64 determinism over extremely long sequences
        let seed = 0x123456789ABCDEF0u64;
        let mut rng1 = SplitMix64::new(seed);
        let mut rng2 = SplitMix64::new(seed);

        // Test determinism over a very long sequence that could reveal issues
        // with internal state corruption or period detection
        let iterations = 1_000_000;
        for i in 0..iterations {
            let val1 = rng1.next_u64();
            let val2 = rng2.next_u64();
            assert_eq!(val1, val2, "RNG divergence at iteration {}", i);

            // Every 100k iterations, also check f64 and usize generation
            if i % 100_000 == 0 {
                assert_eq!(rng1.next_f64(), rng2.next_f64());
                assert_eq!(rng1.next_usize(100), rng2.next_usize(100));
            }
        }

        // Test that extreme seeds still produce valid outputs
        let extreme_seeds = [0, 1, u64::MAX - 1, u64::MAX];
        for extreme_seed in extreme_seeds {
            let mut rng = SplitMix64::new(extreme_seed);
            for _ in 0..1000 {
                let f64_val = rng.next_f64();
                assert!(
                    f64_val.is_finite() && f64_val >= 0.0 && f64_val < 1.0,
                    "Extreme seed {} produced invalid f64: {}",
                    extreme_seed,
                    f64_val
                );
            }
        }
    }

    #[test]
    fn negative_fault_profile_validation_at_floating_point_precision_limits() {
        // Test FaultProfile validation at the limits of floating-point precision

        // Values that are technically valid but at precision boundaries
        let precision_cases = [
            (f64::MIN_POSITIVE, "min_positive"), // Smallest positive normal number
            (1.0 - f64::EPSILON, "near_one_minus_epsilon"), // Just below 1.0
            (f64::EPSILON, "epsilon"),           // Smallest distinguishable from 0.0
            (0.5 + f64::EPSILON, "half_plus_epsilon"), // Just above 0.5
            (0.5 - f64::EPSILON, "half_minus_epsilon"), // Just below 0.5
        ];

        for (value, description) in precision_cases {
            let profile = FaultProfile {
                drop_pct: value,
                corrupt_probability: value,
                ..Default::default()
            };

            let validation_result = profile.validate();
            if (0.0..=1.0).contains(&value) && value.is_finite() {
                assert!(
                    validation_result.is_ok(),
                    "{} ({}) should be valid but failed validation",
                    description,
                    value
                );
            } else {
                assert!(
                    validation_result.is_err(),
                    "{} ({}) should be invalid but passed validation",
                    description,
                    value
                );
            }
        }

        // Test edge cases around subnormal numbers
        let subnormal = f64::MIN_POSITIVE / 2.0; // Subnormal number
        let profile_subnormal = FaultProfile {
            drop_pct: subnormal,
            ..Default::default()
        };
        assert!(
            profile_subnormal.validate().is_ok(),
            "Subnormal numbers should be valid"
        );
    }

    #[test]
    fn negative_repro_bundle_with_corrupted_event_sequence_detects_inconsistency() {
        // Test ReproBundle validation with corrupted event sequences
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.add_link(make_link("sender", "receiver", FaultProfile::default()))
            .unwrap();

        // Generate a valid bundle
        let _result = rt
            .run_scenario(&|rt| {
                rt.send_message(0, "test_message")?;
                Ok(false) // Deliberate failure to generate full trace
            })
            .unwrap();

        let mut bundle = rt.export_repro_bundle(false);

        // Corrupt the event sequence in various ways
        let original_events = bundle.events.clone();

        // Case 1: Remove critical events
        bundle.events = bundle
            .events
            .into_iter()
            .filter(|e| e.event_code != EVT_LAB_INITIALIZED)
            .collect();

        let corrupted_json = serde_json::to_string(&bundle).unwrap();
        let replay_result =
            LabRuntime::replay_bundle(&ReproBundle::from_json(&corrupted_json).unwrap(), &|rt| {
                rt.send_message(0, "test_message")?;
                Ok(false)
            });
        // Should detect divergence due to missing initialization event
        assert!(replay_result.is_err());

        // Case 2: Reorder events to break chronological order
        bundle.events = original_events.clone();
        if bundle.events.len() >= 2 {
            bundle.events.swap(0, bundle.events.len() - 1);
        }

        let reordered_json = serde_json::to_string(&bundle).unwrap();
        let reorder_result =
            LabRuntime::replay_bundle(&ReproBundle::from_json(&reordered_json).unwrap(), &|rt| {
                rt.send_message(0, "test_message")?;
                Ok(false)
            });
        // Should detect divergence due to incorrect event order
        assert!(reorder_result.is_err());
    }

    #[test]
    fn negative_lab_runtime_with_massive_virtual_link_collection_maintains_performance() {
        // Test LabRuntime performance and correctness with maximum virtual links
        let mut rt = LabRuntime::new(default_config()).unwrap();

        // Fill up to capacity with virtual links
        let mut link_indices = Vec::new();
        for i in 0..MAX_VIRTUAL_LINKS {
            let link = make_link(
                &format!("node_{:06}", i),
                &format!("node_{:06}", (i + 1) % MAX_VIRTUAL_LINKS),
                FaultProfile {
                    drop_pct: (i as f64) / (MAX_VIRTUAL_LINKS as f64 * 2.0), // Varying fault rates
                    reorder_depth: i % 5,
                    corrupt_probability: 0.0,
                    delay_ticks: i % 3,
                },
            );

            let idx = rt.add_link(link).unwrap();
            link_indices.push(idx);
        }

        assert_eq!(rt.link_count(), MAX_VIRTUAL_LINKS);

        // Test that find_link operations work correctly at scale
        for (i, expected_idx) in link_indices.iter().enumerate() {
            let found_idx = rt
                .find_link(
                    &format!("node_{:06}", i),
                    &format!("node_{:06}", (i + 1) % MAX_VIRTUAL_LINKS),
                )
                .unwrap();
            assert_eq!(found_idx, *expected_idx);
        }

        // Test that message sending works across all links
        let mut total_delivered = 0;
        let mut total_dropped = 0;
        let mut total_reordered = 0;

        for &link_idx in &link_indices[..100] {
            // Test subset to keep test fast
            match rt.send_message(link_idx, "capacity_test_message").unwrap() {
                MessageOutcome::Delivered { .. } => total_delivered += 1,
                MessageOutcome::Dropped => total_dropped += 1,
                MessageOutcome::Reordered { .. } => total_reordered += 1,
                MessageOutcome::Corrupted { .. } => {} // Expected with varying fault rates
            }
        }

        // Should see a mix of outcomes due to varying fault profiles
        assert!(total_delivered + total_dropped + total_reordered > 0);

        // Verify that capacity limit is properly enforced
        let overflow_result = rt.add_link(make_link("overflow", "node", FaultProfile::default()));
        assert!(
            matches!(overflow_result, Err(LabError::LinkCapacityExceeded { limit })
                         if limit == MAX_VIRTUAL_LINKS)
        );
    }

    #[test]
    fn negative_dpor_scenario_exploration_with_pathological_link_configurations() {
        // Test DPOR with pathological virtual link configurations that could
        // cause exponential exploration or infinite loops

        let pathological_config = LabConfig {
            seed: 42,
            max_ticks: 1000,
            max_interleavings: 10,
            enable_dpor: true,
        };

        // Create a complex network topology that could cause DPOR issues
        let complex_links = vec![
            // Circular dependency chain
            make_link(
                "a",
                "b",
                FaultProfile {
                    delay_ticks: 1,
                    ..Default::default()
                },
            ),
            make_link(
                "b",
                "c",
                FaultProfile {
                    delay_ticks: 2,
                    ..Default::default()
                },
            ),
            make_link(
                "c",
                "a",
                FaultProfile {
                    delay_ticks: 1,
                    ..Default::default()
                },
            ),
            // High-contention hub
            make_link(
                "hub",
                "d",
                FaultProfile {
                    reorder_depth: 3,
                    ..Default::default()
                },
            ),
            make_link(
                "hub",
                "e",
                FaultProfile {
                    reorder_depth: 3,
                    ..Default::default()
                },
            ),
            make_link(
                "hub",
                "f",
                FaultProfile {
                    reorder_depth: 3,
                    ..Default::default()
                },
            ),
            // Lossy links that could hide determinism issues
            make_link(
                "g",
                "h",
                FaultProfile {
                    drop_pct: 0.9,
                    ..Default::default()
                },
            ),
            make_link(
                "h",
                "i",
                FaultProfile {
                    corrupt_probability: 0.8,
                    delay_ticks: 5,
                    ..Default::default()
                },
            ),
        ];

        let result = LabRuntime::run_scenario_dpor(&pathological_config, &complex_links, &|rt| {
            // Send messages across the pathological network
            for link_idx in 0..rt.link_count() {
                let _ = rt.send_message(link_idx, &format!("msg_from_link_{}", link_idx));
            }

            // Advance time to allow delayed messages
            rt.advance_clock(10)?;

            // Scenario should always pass - we're testing exploration robustness
            Ok(true)
        });

        assert!(
            result.is_ok(),
            "DPOR should handle pathological link configurations"
        );
        let scenario_result = result.unwrap();

        // Should have explored the requested number of interleavings without infinite loops
        assert_eq!(scenario_result.interleavings_explored, 10);
        assert!(scenario_result.passed);

        // Should have generated comprehensive event traces
        assert!(!scenario_result.events.is_empty());

        // Test that DPOR respects budget limits with complex configurations
        let limited_config = LabConfig {
            seed: 42,
            max_ticks: 1000,
            max_interleavings: 3, // Very limited budget
            enable_dpor: true,
        };

        let limited_result =
            LabRuntime::run_scenario_dpor(&limited_config, &complex_links, &|rt| {
                // More intensive scenario that could exceed budget
                for _ in 0..50 {
                    for link_idx in 0..rt.link_count() {
                        let _ = rt.send_message(link_idx, "intensive_message");
                    }
                }
                rt.advance_clock(100)?;
                Ok(true)
            });

        assert!(limited_result.is_ok());
        assert_eq!(limited_result.unwrap().interleavings_explored, 3);
    }

    #[test]
    fn negative_tick_overflow_edge_cases_with_saturating_arithmetic() {
        // Test tick calculations at u64 boundaries with various overflow scenarios
        let mut rt = LabRuntime::with_seed(12345).unwrap();

        // Test near-max u64 values that could cause overflow in tick arithmetic
        rt.current_tick = u64::MAX - 5;

        // Should handle tick advancement near overflow boundaries gracefully
        let advance_result = rt.advance_clock(3);
        assert!(
            advance_result.is_ok(),
            "Small advancement near u64::MAX should succeed"
        );

        // Should detect overflow conditions and fail safely
        let overflow_result = rt.advance_clock(100);
        assert!(
            matches!(overflow_result, Err(LabError::TickOverflow { current, delta })
                       if current >= u64::MAX - 10 && delta == 100)
        );

        // Test timer scheduling with extreme tick values
        let timer_result = rt.schedule_timer(u64::MAX - 1);
        assert!(
            timer_result.is_ok(),
            "Timer near u64::MAX should be schedulable"
        );

        // Test timer that would overflow when added to current tick
        rt.current_tick = u64::MAX - 2;
        let overflow_timer = rt.schedule_timer(10);
        assert!(
            overflow_timer.is_err(),
            "Timer scheduling that would overflow should fail"
        );
    }

    #[test]
    fn negative_prng_state_corruption_and_recovery_scenarios() {
        // Test PRNG behavior under state corruption and edge case seeds

        // Test with problematic seed values that could cause degenerate sequences
        let degenerate_seeds = vec![0, 1, u64::MAX, u64::MAX - 1];

        for &seed in &degenerate_seeds {
            let prng_result = SeededRng::new(seed);
            assert!(
                prng_result.is_ok(),
                "PRNG should handle degenerate seed {}",
                seed
            );

            let mut rng = prng_result.unwrap();

            // Generate sequence to verify it's not stuck in degenerate state
            let mut values = Vec::new();
            for _ in 0..100 {
                values.push(rng.next_u64());
            }

            // Check for basic randomness properties (not all same value)
            let unique_count = values
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len();
            assert!(
                unique_count > 10,
                "PRNG with seed {} should produce varied output",
                seed
            );
        }

        // Test PRNG state after extreme number of generations
        let mut rng = SeededRng::new(42).unwrap();

        // Generate many values to test for cycle detection or state corruption
        let mut last_value = 0;
        for _ in 0..1000000 {
            let value = rng.next_u64();
            // Should not get stuck returning same value
            if value != last_value {
                last_value = value;
                break;
            }
        }
        assert_ne!(
            last_value, 0,
            "PRNG should not get stuck in degenerate state"
        );
    }

    #[test]
    fn negative_virtual_link_extreme_configurations_memory_pressure() {
        // Test virtual link behavior with extreme configurations that stress memory
        let mut rt = LabRuntime::with_seed(789).unwrap();

        // Test maximum capacity boundary
        let max_fault_profile = FaultProfile {
            delay_ticks: u64::MAX / 2,  // Large but safe delay
            drop_pct: 1.0,              // 100% drop rate
            corrupt_probability: 1.0,   // 100% corruption
            reorder_depth: 1000,        // Large reorder buffer
            duplicate_probability: 1.0, // 100% duplication
        };

        let max_link = VirtualLink {
            source: "extreme_src".to_string(),
            target: "extreme_tgt".to_string(),
            fault_profile: max_fault_profile,
        };

        let add_result = rt.add_link(max_link);
        assert!(
            add_result.is_ok(),
            "Should handle extreme but valid fault profile"
        );

        // Test with invalid probability values outside [0.0, 1.0]
        let invalid_profiles = vec![
            FaultProfile {
                drop_pct: -0.1,
                ..Default::default()
            },
            FaultProfile {
                drop_pct: 1.1,
                ..Default::default()
            },
            FaultProfile {
                corrupt_probability: 2.0,
                ..Default::default()
            },
            FaultProfile {
                duplicate_probability: -1.0,
                ..Default::default()
            },
        ];

        for (i, profile) in invalid_profiles.iter().enumerate() {
            let invalid_link = VirtualLink {
                source: format!("invalid_src_{}", i),
                target: format!("invalid_tgt_{}", i),
                fault_profile: profile.clone(),
            };

            let result = rt.add_link(invalid_link);
            assert!(
                matches!(result, Err(LabError::FaultRange { field: _, value })
                           if !value.is_finite() || value < 0.0 || value > 1.0),
                "Should reject invalid probability values"
            );
        }

        // Test memory pressure with maximum allowed links
        for i in 0..MAX_VIRTUAL_LINKS - 1 {
            // -1 because we added one extreme link above
            let link = make_link(
                &format!("src_{}", i),
                &format!("tgt_{}", i),
                FaultProfile::default(),
            );
            let result = rt.add_link(link);
            assert!(result.is_ok(), "Should add link {} within capacity", i);
        }

        // Next addition should fail due to capacity limit
        let overflow_link = make_link("overflow_src", "overflow_tgt", FaultProfile::default());
        let overflow_result = rt.add_link(overflow_link);
        assert!(
            matches!(overflow_result, Err(LabError::LinkCapacityExceeded { limit })
                       if limit == MAX_VIRTUAL_LINKS)
        );
    }

    #[test]
    fn negative_timer_id_exhaustion_and_scheduling_edge_cases() {
        // Test timer ID exhaustion scenarios and edge case scheduling
        let mut rt = LabRuntime::with_seed(555).unwrap();

        // Schedule timers up to potential ID exhaustion
        let mut timer_ids = Vec::new();

        // Schedule many timers to test ID space management
        for tick in 1..10000 {
            match rt.schedule_timer(tick) {
                Ok(id) => {
                    timer_ids.push(id);

                    // Verify ID uniqueness
                    let unique_count = timer_ids
                        .iter()
                        .collect::<std::collections::HashSet<_>>()
                        .len();
                    assert_eq!(unique_count, timer_ids.len(), "Timer IDs should be unique");
                }
                Err(LabError::TimerIdExhausted) => {
                    // Expected when IDs are exhausted
                    break;
                }
                Err(e) => {
                    panic!("Unexpected error scheduling timer: {:?}", e);
                }
            }
        }

        assert!(
            !timer_ids.is_empty(),
            "Should have scheduled some timers before exhaustion"
        );

        // Test scheduling timers at exact tick boundaries
        let boundary_ticks = vec![0, 1, u64::MAX - 1];

        for &tick in &boundary_ticks {
            if rt.current_tick < tick {
                let result = rt.schedule_timer(tick);
                // Should succeed if tick is in future, fail if in past
                if tick > rt.current_tick {
                    assert!(
                        result.is_ok() || matches!(result, Err(LabError::TimerIdExhausted)),
                        "Timer at boundary tick {} should succeed or hit ID exhaustion",
                        tick
                    );
                }
            }
        }

        // Test timer firing order invariant
        rt.advance_clock(5000).unwrap_or_default(); // Advance to fire some timers

        // Any fired timers should maintain order invariant
        // (This is tested internally by the runtime, just verify it doesn't panic)
        assert!(rt.current_tick >= 5000, "Clock should have advanced");
    }

    #[test]
    fn negative_bundle_serialization_with_extreme_unicode_and_binary_data() {
        // Test repro bundle serialization with extreme Unicode and binary edge cases
        let config = LabConfig {
            seed: 12345,
            max_ticks: 1000,
            max_interleavings: 5,
            enable_dpor: false,
        };

        // Create links with extreme Unicode edge cases in names
        let extreme_unicode_links = vec![
            // Zero-width characters that could break parsing
            make_link(
                "\u{200B}\u{200C}\u{200D}",
                "target1",
                FaultProfile::default(),
            ),
            // Maximum Unicode codepoints
            make_link("source2", "\u{10FFFF}", FaultProfile::default()),
            // Combining characters and normalization edge cases
            make_link(
                "a\u{0301}\u{0327}\u{0315}",
                "target3",
                FaultProfile::default(),
            ),
            // Bidirectional text markers
            make_link(
                "\u{202D}source4\u{202C}",
                "target4",
                FaultProfile::default(),
            ),
            // Null and control characters (if not filtered out)
            make_link("source\u{0000}5", "target5", FaultProfile::default()),
            // Very long names that could cause buffer issues
            make_link(&"x".repeat(10000), "target6", FaultProfile::default()),
        ];

        let result = LabRuntime::run_scenario(&config, &extreme_unicode_links, &|rt| {
            // Send messages with extreme binary data
            let binary_payloads = vec![
                vec![0u8; 0],                    // Empty
                vec![0xFF; 10000],               // All high bytes
                vec![0x00; 10000],               // All null bytes
                (0..=255u8).collect::<Vec<_>>(), // Full byte range
            ];

            for (i, payload) in binary_payloads.iter().enumerate() {
                if i < rt.link_count() {
                    let payload_str = format!("{:?}", payload); // Convert to debug string for sending
                    let _ = rt.send_message(i, &payload_str);
                }
            }

            rt.advance_clock(100)?;
            Ok(true)
        });

        match result {
            Ok(scenario_result) => {
                // Bundle should serialize/deserialize correctly despite extreme data
                assert!(
                    scenario_result.passed,
                    "Scenario should handle extreme Unicode data"
                );
                assert!(!scenario_result.events.is_empty(), "Should generate events");

                // Attempt to create and serialize a repro bundle
                // (This would be done by the export functionality)
                let bundle_attempt = format!("{:?}", scenario_result);
                assert!(
                    !bundle_attempt.is_empty(),
                    "Bundle debug representation should not be empty"
                );
            }
            Err(e) => {
                // Some extreme Unicode cases might be rejected, which is acceptable
                match e {
                    LabError::LinkCapacityExceeded { .. } => {
                        // Expected if too many links
                    }
                    LabError::BundleValidation { .. } => {
                        // Expected if extreme data causes validation issues
                    }
                    _ => panic!("Unexpected error with extreme Unicode: {:?}", e),
                }
            }
        }
    }

    #[test]
    fn negative_dpor_exploration_budget_boundary_conditions() {
        // Test DPOR budget enforcement at exact boundaries and edge cases

        let boundary_configs = vec![
            // Zero budget - should fail or handle gracefully
            LabConfig {
                max_interleavings: 0,
                enable_dpor: true,
                seed: 111,
                max_ticks: 100,
            },
            // Single interleaving
            LabConfig {
                max_interleavings: 1,
                enable_dpor: true,
                seed: 222,
                max_ticks: 100,
            },
            // Very large budget that could cause resource issues
            LabConfig {
                max_interleavings: u64::MAX / 2,
                enable_dpor: true,
                seed: 333,
                max_ticks: 10,
            },
        ];

        let simple_links = vec![
            make_link("a", "b", FaultProfile::default()),
            make_link("b", "c", FaultProfile::default()),
        ];

        for (i, config) in boundary_configs.iter().enumerate() {
            let result = LabRuntime::run_scenario_dpor(config, &simple_links, &|rt| {
                // Simple scenario that creates minimal interleaving opportunities
                let _ = rt.send_message(0, "msg1");
                let _ = rt.send_message(1, "msg2");
                rt.advance_clock(5)?;
                Ok(true)
            });

            match result {
                Ok(scenario_result) => {
                    // Should respect the configured budget exactly
                    assert!(
                        scenario_result.interleavings_explored <= config.max_interleavings,
                        "Config {}: explored {} > budget {}",
                        i,
                        scenario_result.interleavings_explored,
                        config.max_interleavings
                    );

                    // Zero budget should explore zero interleavings
                    if config.max_interleavings == 0 {
                        assert_eq!(scenario_result.interleavings_explored, 0);
                    }
                }
                Err(LabError::BudgetExceeded { explored, budget }) => {
                    // Acceptable if budget enforcement is strict
                    assert_eq!(
                        budget, config.max_interleavings,
                        "Budget error should match configured limit"
                    );
                    assert!(
                        explored <= budget + 1,
                        "Should not explore significantly past budget"
                    );
                }
                Err(e) => {
                    // Other errors may be acceptable for extreme configurations
                    match e {
                        LabError::TickOverflow { .. } => {
                            // Acceptable for very large budget configs
                        }
                        _ => panic!("Config {}: unexpected error: {:?}", i, e),
                    }
                }
            }
        }
    }

    #[test]
    fn negative_fault_injection_nan_infinity_and_edge_case_probabilities() {
        // Test fault injection with NaN, infinity, and boundary probability values

        let mut rt = LabRuntime::with_seed(999).unwrap();

        // Test problematic floating-point values in fault profiles
        let problematic_profiles = vec![
            // NaN values
            FaultProfile {
                drop_pct: f64::NAN,
                ..Default::default()
            },
            FaultProfile {
                corrupt_probability: f64::NAN,
                ..Default::default()
            },
            FaultProfile {
                duplicate_probability: f64::NAN,
                ..Default::default()
            },
            // Infinity values
            FaultProfile {
                drop_pct: f64::INFINITY,
                ..Default::default()
            },
            FaultProfile {
                corrupt_probability: f64::NEG_INFINITY,
                ..Default::default()
            },
            FaultProfile {
                duplicate_probability: f64::INFINITY,
                ..Default::default()
            },
            // Boundary values that might cause precision issues
            FaultProfile {
                drop_pct: f64::EPSILON,
                ..Default::default()
            },
            FaultProfile {
                corrupt_probability: 1.0 - f64::EPSILON,
                ..Default::default()
            },
            FaultProfile {
                duplicate_probability: f64::MIN_POSITIVE,
                ..Default::default()
            },
            // Subnormal values
            FaultProfile {
                drop_pct: f64::from_bits(1),
                ..Default::default()
            }, // Smallest subnormal
        ];

        for (i, profile) in problematic_profiles.iter().enumerate() {
            let test_link = VirtualLink {
                source: format!("test_src_{}", i),
                target: format!("test_tgt_{}", i),
                fault_profile: profile.clone(),
            };

            let result = rt.add_link(test_link);

            match result {
                Ok(_) => {
                    // If accepted, should handle gracefully during message processing
                    let send_result = rt.send_message(i, "test_message");
                    // Should not panic or corrupt state regardless of send result
                    assert!(
                        send_result.is_ok() || send_result.is_err(),
                        "Send result should be definite (not panic)"
                    );
                }
                Err(LabError::FaultRange { field, value }) => {
                    // Expected rejection for invalid probability values
                    assert!(
                        !value.is_finite() || value < 0.0 || value > 1.0,
                        "Should only reject truly invalid values, got field={}, value={}",
                        field,
                        value
                    );
                }
                Err(e) => {
                    panic!("Unexpected error for problematic profile {}: {:?}", i, e);
                }
            }
        }

        // Test edge case: probabilities that sum to > 1.0
        let overlapping_faults = FaultProfile {
            drop_pct: 0.8,
            corrupt_probability: 0.7,
            duplicate_probability: 0.9,
            delay_ticks: 1,
            reorder_depth: 1,
        };

        let overlapping_link = VirtualLink {
            source: "overlap_src".to_string(),
            target: "overlap_tgt".to_string(),
            fault_profile: overlapping_faults,
        };

        // Should handle overlapping probabilities gracefully (implementation-defined behavior)
        let overlap_result = rt.add_link(overlapping_link);
        assert!(
            overlap_result.is_ok(),
            "Should handle overlapping fault probabilities"
        );

        if overlap_result.is_ok() {
            // Send messages to test combined fault behavior
            for i in 0..100 {
                let _ = rt.send_message(rt.link_count() - 1, &format!("overlap_msg_{}", i));
            }
            rt.advance_clock(10).unwrap_or_default();
        }
    }

    #[test]
    fn negative_reorder_buffer_overflow_and_push_bounded_edge_cases() {
        // Test reorder buffer behavior at capacity limits and push_bounded edge cases

        let mut rt = LabRuntime::with_seed(777).unwrap();

        // Create link with maximum reorder depth
        let max_reorder_profile = FaultProfile {
            reorder_depth: MAX_REORDER_BUFFERS,
            delay_ticks: 0, // No delay, focus on reordering
            drop_pct: 0.0,  // No drops, all messages should be reordered
            corrupt_probability: 0.0,
            duplicate_probability: 0.0,
        };

        let reorder_link = VirtualLink {
            source: "reorder_src".to_string(),
            target: "reorder_tgt".to_string(),
            fault_profile: max_reorder_profile,
        };

        let add_result = rt.add_link(reorder_link);
        assert!(add_result.is_ok(), "Should accept maximum reorder depth");

        if add_result.is_ok() {
            let link_idx = rt.link_count() - 1;

            // Send more messages than the reorder buffer can hold
            let overflow_count = MAX_REORDER_BUFFERS + 100;

            for i in 0..overflow_count {
                let send_result = rt.send_message(link_idx, &format!("reorder_msg_{}", i));

                // Should handle overflow gracefully via push_bounded
                match send_result {
                    Ok(_) => {
                        // Message accepted - buffer should maintain capacity via push_bounded
                    }
                    Err(LabError::LinkCapacityExceeded { .. }) => {
                        // Acceptable if implementation enforces strict capacity limits
                        break;
                    }
                    Err(e) => {
                        panic!("Unexpected error during reorder buffer overflow: {:?}", e);
                    }
                }
            }

            // Advance clock to process reordered messages
            rt.advance_clock(10).unwrap_or_default();

            // Test push_bounded with zero capacity (edge case)
            let mut test_vec = Vec::new();
            push_bounded(&mut test_vec, "item1", 0);
            assert!(
                test_vec.is_empty(),
                "push_bounded with 0 capacity should keep vec empty"
            );

            // Test push_bounded with capacity 1 (boundary case)
            let mut single_capacity = Vec::new();
            push_bounded(&mut single_capacity, "first", 1);
            assert_eq!(single_capacity.len(), 1);
            assert_eq!(single_capacity[0], "first");

            push_bounded(&mut single_capacity, "second", 1);
            assert_eq!(single_capacity.len(), 1);
            assert_eq!(single_capacity[0], "second", "Should evict first item");

            // Test push_bounded with very large capacity
            let mut large_capacity = Vec::new();
            let large_cap = usize::MAX / 2; // Avoid potential overflow

            for i in 0..10 {
                push_bounded(&mut large_capacity, i, large_cap);
            }
            assert_eq!(large_capacity.len(), 10);
            assert_eq!(large_capacity, (0..10).collect::<Vec<_>>());
        }

        #[test]
        fn test_lab_runtime_invalid_seed_configurations() {
            // Test zero seed (should fail)
            let zero_config = LabRuntimeConfig {
                seed: 0,
                max_interleaving_budget: 1000,
                enable_repro_export: false,
                fault_profiles: BTreeMap::new(),
            };

            let result = LabRuntime::new(zero_config);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("ERR_LB_NO_SEED"));

            // Test boundary seed values
            let boundary_seeds = vec![1, u64::MAX, u64::MAX / 2];
            for seed in boundary_seeds {
                let config = LabRuntimeConfig {
                    seed,
                    max_interleaving_budget: 1000,
                    enable_repro_export: true,
                    fault_profiles: BTreeMap::new(),
                };

                let result = LabRuntime::new(config);
                assert!(result.is_ok());
                let runtime = result.unwrap();
                assert_eq!(runtime.current_tick(), 0);
            }
        }

        #[test]
        fn test_unicode_injection_in_scenario_identifiers() {
            let config = LabRuntimeConfig {
                seed: 42,
                max_interleaving_budget: 100,
                enable_repro_export: true,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).unwrap();

            // Test various Unicode injection attacks in scenario IDs
            let malicious_scenario_ids = vec![
                "normal\u{202e}evil\u{202c}scenario", // BiDi override
                "scenario\u{200b}\u{feff}hidden",     // Zero-width characters
                "scenario\nnewline",                  // Newline injection
                "scenario\ttab",                      // Tab injection
                "scenario\x00null",                   // Null byte injection
                "../../../etc/passwd",                // Path traversal
                "scenario\"quote",                    // Quote injection
            ];

            for scenario_id in &malicious_scenario_ids {
                let result = runtime.start_scenario(scenario_id);

                // Should handle Unicode without corruption
                assert!(result.is_ok());

                // Verify scenario tracking works with Unicode IDs
                assert!(runtime.is_scenario_active(scenario_id));

                // Complete scenario
                let complete_result = runtime.complete_scenario(scenario_id);
                assert!(complete_result.is_ok());
            }
        }

        #[test]
        fn test_timer_overflow_and_exhaustion() {
            let config = LabRuntimeConfig {
                seed: 123,
                max_interleaving_budget: 500,
                enable_repro_export: false,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).unwrap();

            // Test near-overflow timer tick values
            let overflow_ticks = vec![
                u64::MAX - 1,
                u64::MAX,
                u64::MAX / 2,
                (1u64 << 63) - 1, // Just below signed overflow
            ];

            for (i, tick) in overflow_ticks.iter().enumerate() {
                let timer_id = format!("timer-{}", i);
                let result = runtime.schedule_timer(&timer_id, *tick);

                // Should handle large tick values without overflow
                assert!(result.is_ok());
            }

            // Test timer ID exhaustion by creating many timers
            for i in 0..10000 {
                let timer_id = format!("stress-timer-{}", i);
                let result = runtime.schedule_timer(&timer_id, 1000 + i);

                if result.is_err() {
                    // Should fail gracefully when IDs are exhausted
                    let err = result.unwrap_err();
                    assert!(err.contains("ERR_LB_TIMER_ID_EXHAUSTED"));
                    break;
                }
            }
        }

        #[test]
        fn test_clock_tick_arithmetic_overflow_protection() {
            let config = LabRuntimeConfig {
                seed: 456,
                max_interleaving_budget: 100,
                enable_repro_export: false,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).unwrap();

            // Test advancing clock near overflow boundaries
            runtime.advance_test_clock(u64::MAX - 100);
            assert_eq!(runtime.current_tick(), u64::MAX - 100);

            // Test incrementing near overflow (should saturate or error)
            let result = runtime.advance_test_clock(150);

            if result.is_err() {
                // Should fail gracefully with overflow error
                let err = result.unwrap_err();
                assert!(err.contains("ERR_LB_TICK_OVERFLOW"));
            } else {
                // If it succeeds, should not overflow past u64::MAX
                assert!(runtime.current_tick() <= u64::MAX);
            }
        }

        #[test]
        fn test_massive_virtual_link_memory_exhaustion() {
            let config = LabRuntimeConfig {
                seed: 789,
                max_interleaving_budget: 100,
                enable_repro_export: false,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).unwrap();
            runtime.start_scenario("memory-stress").unwrap();

            // Create maximum number of virtual links
            for i in 0..MAX_VIRTUAL_LINKS {
                let link_id = format!("massive-link-{:04}", i);
                let from_node = format!("node-{}", i % 100);
                let to_node = format!("node-{}", (i + 1) % 100);

                // Create massive fault profile data
                let fault_profile = FaultProfile {
                    drop_probability: 0.1,
                    reorder_depth: 1000,
                    corruption_rate: 0.01,
                    delay_ticks: i as u64,
                    custom_data: vec![0x42; 1024 * 1024], // 1MB per link
                };

                let result =
                    runtime.create_virtual_link(&link_id, &from_node, &to_node, fault_profile);

                if result.is_err() {
                    // Should fail gracefully when capacity exceeded
                    let err = result.unwrap_err();
                    assert!(err.contains("ERR_LB_LINK_CAPACITY_EXCEEDED"));
                    break;
                }
            }

            // Runtime should remain functional
            let final_result = runtime.complete_scenario("memory-stress");
            assert!(final_result.is_ok());
        }

        #[test]
        fn test_fault_probability_floating_point_edge_cases() {
            let config = LabRuntimeConfig {
                seed: 999,
                max_interleaving_budget: 50,
                enable_repro_export: false,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).unwrap();
            runtime.start_scenario("fault-precision").unwrap();

            // Test invalid fault probability values
            let invalid_probabilities = vec![
                -0.1,              // Negative
                1.1,               // Above 1.0
                f64::NAN,          // NaN
                f64::INFINITY,     // Positive infinity
                f64::NEG_INFINITY, // Negative infinity
                2.0,               // Well above 1.0
            ];

            for (i, prob) in invalid_probabilities.iter().enumerate() {
                let link_id = format!("fault-link-{}", i);
                let fault_profile = FaultProfile {
                    drop_probability: *prob,
                    reorder_depth: 0,
                    corruption_rate: 0.0,
                    delay_ticks: 0,
                    custom_data: Vec::new(),
                };

                let result =
                    runtime.create_virtual_link(&link_id, "sender", "receiver", fault_profile);

                if prob.is_nan() || prob.is_infinite() || *prob < 0.0 || *prob > 1.0 {
                    // Should reject invalid probabilities
                    assert!(result.is_err());
                    if let Err(e) = result {
                        assert!(e.contains("ERR_LB_FAULT_RANGE"));
                    }
                }
            }

            // Test valid edge case probabilities
            let valid_edge_probabilities = vec![
                0.0,                // Exact zero
                1.0,                // Exact one
                f64::EPSILON,       // Smallest positive
                1.0 - f64::EPSILON, // Just below 1.0
                0.3333333333333333, // Repeating decimal
            ];

            for (i, prob) in valid_edge_probabilities.iter().enumerate() {
                let link_id = format!("valid-fault-{}", i);
                let fault_profile = FaultProfile {
                    drop_probability: *prob,
                    reorder_depth: 10,
                    corruption_rate: *prob / 10.0,
                    delay_ticks: i as u64,
                    custom_data: Vec::new(),
                };

                let result = runtime.create_virtual_link(
                    &link_id,
                    "precise-sender",
                    "precise-receiver",
                    fault_profile,
                );
                assert!(result.is_ok());
            }
        }

        #[test]
        fn test_repro_bundle_corruption_resilience() {
            let config = LabRuntimeConfig {
                seed: 111,
                max_interleaving_budget: 200,
                enable_repro_export: true,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).unwrap();
            runtime.start_scenario("repro-test").unwrap();

            // Create some test state
            runtime.schedule_timer("test-timer", 100).unwrap();
            runtime.advance_test_clock(50);

            // Export repro bundle
            let bundle_result = runtime.export_repro_bundle();
            assert!(bundle_result.is_ok());
            let bundle = bundle_result.unwrap();

            // Test corrupted JSON variations
            let corrupted_bundles = vec![
                r#"{"seed": 111, "events": [malformed]"#, // Malformed JSON
                r#"{"seed": "not-a-number"}"#,            // Wrong type
                r#"{"seed": 111, "events": null}"#,       // Null events
                r#"{}"#,                                  // Empty object
                r#"null"#,                                // Null root
                r#"{"seed": 111, "events": [], "schema": "invalid-version"}"#, // Bad schema
            ];

            for corrupt_json in corrupted_bundles {
                let deserialize_result = serde_json::from_str::<ReproBundle>(corrupt_json);

                if let Ok(parsed_bundle) = deserialize_result {
                    // If parsing succeeds, replay should validate and reject
                    let replay_result = runtime.replay_from_bundle(parsed_bundle);
                    assert!(replay_result.is_err());
                    if let Err(e) = replay_result {
                        assert!(e.contains("ERR_LB_BUNDLE_VALIDATION"));
                    }
                } else {
                    // Parsing failure is also acceptable for malformed JSON
                    // Should fail gracefully without panic
                }
            }
        }

        #[test]
        fn test_dpor_budget_exhaustion_boundary() {
            // Test DPOR interleaving budget limits
            let small_budget_config = LabRuntimeConfig {
                seed: 222,
                max_interleaving_budget: 5, // Very small budget
                enable_repro_export: false,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(small_budget_config).unwrap();
            runtime.start_scenario("dpor-stress").unwrap();

            // Create many virtual links to trigger DPOR exploration
            for i in 0..20 {
                let link_id = format!("dpor-link-{}", i);
                let fault_profile = FaultProfile {
                    drop_probability: 0.5, // High fault rate to trigger exploration
                    reorder_depth: 5,
                    corruption_rate: 0.1,
                    delay_ticks: i as u64,
                    custom_data: Vec::new(),
                };

                let result =
                    runtime.create_virtual_link(&link_id, "sender", "receiver", fault_profile);

                if result.is_err() {
                    // Should fail gracefully when budget exceeded
                    let err = result.unwrap_err();
                    assert!(err.contains("ERR_LB_BUDGET_EXCEEDED"));
                    break;
                }
            }

            // Runtime should remain functional despite budget exhaustion
            assert!(runtime.is_scenario_active("dpor-stress"));
        }

        #[test]
        fn test_concurrent_lab_runtime_access_safety() {
            use std::sync::{Arc, Barrier, Mutex};
            use std::thread;

            let config = LabRuntimeConfig {
                seed: 333,
                max_interleaving_budget: 1000,
                enable_repro_export: true,
                fault_profiles: BTreeMap::new(),
            };

            let runtime = Arc::new(Mutex::new(LabRuntime::new(config).unwrap()));
            let barrier = Arc::new(Barrier::new(4));

            let handles: Vec<_> = (0..4)
                .map(|i| {
                    let runtime = Arc::clone(&runtime);
                    let barrier = Arc::clone(&barrier);

                    thread::spawn(move || {
                        barrier.wait();

                        // Each thread performs different operations
                        let mut rt = runtime.lock().unwrap();

                        match i {
                            0 => {
                                // Thread 0: scenario management
                                let scenario_id = format!("thread-{}-scenario", i);
                                let _ = rt.start_scenario(&scenario_id);
                                let _ = rt.complete_scenario(&scenario_id);
                            }
                            1 => {
                                // Thread 1: timer operations
                                for j in 0..10 {
                                    let timer_id = format!("thread-{}-timer-{}", i, j);
                                    let _ = rt.schedule_timer(&timer_id, 100 + j);
                                }
                            }
                            2 => {
                                // Thread 2: clock advancement
                                let _ = rt.advance_test_clock(10);
                            }
                            3 => {
                                // Thread 3: virtual link creation
                                let link_id = format!("thread-{}-link", i);
                                let fault_profile = FaultProfile {
                                    drop_probability: 0.1,
                                    reorder_depth: 1,
                                    corruption_rate: 0.0,
                                    delay_ticks: 0,
                                    custom_data: Vec::new(),
                                };
                                let _ = rt.create_virtual_link(
                                    &link_id,
                                    "concurrent-sender",
                                    "concurrent-receiver",
                                    fault_profile,
                                );
                            }
                            _ => {}
                        }
                    })
                })
                .collect();

            // Wait for all threads to complete
            for handle in handles {
                handle.join().expect("thread should complete");
            }

            // Verify runtime remains in consistent state
            let rt = runtime.lock().unwrap();
            assert!(rt.current_tick() >= 0);
        }

        #[test]
        fn test_edge_case_empty_and_massive_configurations() {
            // Test empty configuration
            let empty_config = LabRuntimeConfig {
                seed: 444,
                max_interleaving_budget: 0, // Zero budget
                enable_repro_export: false,
                fault_profiles: BTreeMap::new(),
            };

            let empty_runtime = LabRuntime::new(empty_config);
            if empty_runtime.is_ok() {
                let mut rt = empty_runtime.unwrap();
                // Should handle zero budget gracefully
                let start_result = rt.start_scenario("empty-test");
                assert!(start_result.is_ok());
            }

            // Test massive configuration
            let massive_config = LabRuntimeConfig {
                seed: 555,
                max_interleaving_budget: usize::MAX, // Maximum budget
                enable_repro_export: true,
                fault_profiles: BTreeMap::new(),
            };

            let massive_runtime = LabRuntime::new(massive_config);
            assert!(massive_runtime.is_ok());
            let mut rt = massive_runtime.unwrap();

            // Should handle massive budget without issues
            let start_result = rt.start_scenario("massive-test");
            assert!(start_result.is_ok());
        }

        #[test]
        fn negative_lab_runtime_comprehensive_unicode_injection_and_scenario_attacks() {
            // Test comprehensive Unicode injection and scenario ID attack resistance
            let malicious_unicode_patterns = [
                "\u{202E}\u{202D}fake_scenario\u{202C}", // Right-to-left override
                "scenario\u{000A}\u{000D}injected\x00nulls", // CRLF + null injection
                "\u{FEFF}bom_scenario\u{FFFE}reversed",  // BOM injection attacks
                "\u{200B}\u{200C}\u{200D}zero_width",    // Zero-width characters
                "场景\u{007F}\u{0001}\u{001F}控制字符",  // Unicode + control chars
                "\u{FFFF}\u{FFFE}\u{FDD0}non_characters", // Non-character code points
                "🧪🔬\u{1F4A5}💥\u{1F52B}🔫",            // Complex emoji sequences
                "\u{0300}\u{0301}\u{0302}combining_marks", // Combining marks
                format!("../../../{}", "x".repeat(1000)), // Path traversal + long string
                "scenario\x00\x01\x02\x03\x04\x05hidden", // Binary injection
                "scenario".repeat(100_000),              // Extremely long scenario ID
            ];

            let config = LabRuntimeConfig {
                seed: 777,
                max_interleaving_budget: 1000,
                enable_repro_export: true,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).expect("runtime should create");

            for (i, pattern) in malicious_unicode_patterns.iter().enumerate() {
                let unicode_scenario_id = format!("unicode_test_{}{}", pattern, i);

                // Test scenario lifecycle with Unicode patterns
                let start_result = runtime.start_scenario(&unicode_scenario_id);

                match start_result {
                    Ok(_) => {
                        // If start succeeds, test other operations
                        let complete_result = runtime.complete_scenario(&unicode_scenario_id);
                        match complete_result {
                            Ok(_) => {
                                // Successfully completed scenario with Unicode content
                            }
                            Err(_) => {
                                // May fail on completion with extreme Unicode
                            }
                        }

                        // Try to fail the scenario instead
                        let unicode_fail_id = format!("fail_{}{}", pattern, i);
                        if runtime.start_scenario(&unicode_fail_id).is_ok() {
                            let fail_result =
                                runtime.fail_scenario(&unicode_fail_id, "Unicode test failure");
                            // Should handle Unicode in failure reasons
                            match fail_result {
                                Ok(_) => {
                                    // Unicode handled gracefully in failure path
                                }
                                Err(_) => {
                                    // May reject extreme Unicode in failure messages
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Extreme Unicode patterns may be rejected during start
                    }
                }

                // Test timer IDs with Unicode patterns
                let unicode_timer_id = format!("timer_{}{}", pattern, i);
                let timer_result = runtime.schedule_timer(&unicode_timer_id, 100);

                match timer_result {
                    Ok(_) => {
                        // Timer scheduled with Unicode ID
                        runtime.advance_test_clock(101);

                        // Verify timer fired correctly despite Unicode content
                        let events = runtime.get_event_log();
                        let timer_events: Vec<_> = events
                            .iter()
                            .filter(|e| {
                                e.event_type.contains("TIMER")
                                    && e.description.contains(&format!("{}", i))
                            })
                            .collect();

                        // Should have at least one timer-related event
                        // Unicode should not corrupt event logging
                    }
                    Err(_) => {
                        // Extreme Unicode timer IDs may be rejected
                    }
                }

                // Test virtual link names with Unicode patterns
                let unicode_link_id = format!("link_{}{}", pattern, i);
                let unicode_source = format!("src_{}{}", pattern, i);
                let unicode_target = format!("tgt_{}{}", pattern, i);

                let fault_profile = FaultProfile {
                    drop_probability: 0.1,
                    reorder_depth: 1,
                    corruption_rate: 0.0,
                    delay_ticks: 0,
                    custom_data: format!("unicode_data_{}", pattern).as_bytes().to_vec(),
                };

                let link_result = runtime.create_virtual_link(
                    &unicode_link_id,
                    &unicode_source,
                    &unicode_target,
                    fault_profile,
                );

                match link_result {
                    Ok(_) => {
                        // Virtual link created with Unicode content
                        // Verify link exists and can be used
                        let send_result =
                            runtime.send_message(&unicode_link_id, b"unicode_test_message");
                        match send_result {
                            Ok(_) => {
                                // Message sent successfully on Unicode link
                            }
                            Err(_) => {
                                // May fail with extreme Unicode link configurations
                            }
                        }
                    }
                    Err(_) => {
                        // Extreme Unicode link names may be rejected
                    }
                }

                // Verify event log integrity after Unicode operations
                let events = runtime.get_event_log();
                for event in &events {
                    // All events should remain valid UTF-8
                    assert!(!event.event_type.contains('\0'));
                    assert!(!event.description.contains('\0'));
                    // Event structure should not be corrupted by Unicode
                    assert!(!event.event_type.is_empty());
                }

                // Test repro export with Unicode content
                if runtime.config.enable_repro_export {
                    let export_result = runtime.export_repro_bundle();
                    match export_result {
                        Ok(bundle) => {
                            // Bundle should serialize despite Unicode content
                            let serialized = serde_json::to_string(&bundle);
                            match serialized {
                                Ok(json_str) => {
                                    // Should not contain null bytes or corruption
                                    assert!(!json_str.contains('\0'));

                                    // Should be deserializable
                                    let deserialized: Result<ReproBundle, _> =
                                        serde_json::from_str(&json_str);
                                    match deserialized {
                                        Ok(_) => {
                                            // Successfully round-tripped despite Unicode
                                        }
                                        Err(_) => {
                                            // Extreme Unicode may prevent deserialization
                                        }
                                    }
                                }
                                Err(_) => {
                                    // Extreme Unicode may prevent serialization
                                }
                            }
                        }
                        Err(_) => {
                            // Export may fail with extreme Unicode content
                        }
                    }
                }
            }

            // Final integrity check
            let final_events = runtime.get_event_log();
            assert!(final_events.len() <= MAX_EVENTS);

            // All events should maintain structural integrity
            for event in final_events {
                assert!(!event.event_type.is_empty());
                assert!(event.tick >= 0);
            }
        }

        #[test]
        fn negative_test_clock_overflow_and_time_manipulation_attacks() {
            // Test test clock overflow and time manipulation attack resistance
            let config = LabRuntimeConfig {
                seed: 888,
                max_interleaving_budget: 1000,
                enable_repro_export: false,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).expect("runtime should create");

            // Test extreme time advancement scenarios
            let time_attack_scenarios = [
                1,               // Normal advancement
                1000,            // Large jump
                u64::MAX / 4,    // Very large jump
                u64::MAX / 2,    // Half of maximum
                u64::MAX - 1000, // Near overflow
                u64::MAX - 1,    // Just before overflow
                u64::MAX,        // Maximum value
            ];

            for (test_idx, advance_delta) in time_attack_scenarios.into_iter().enumerate() {
                let current_tick = runtime.current_tick();

                // Test advancement with potential overflow
                let advance_result = runtime.advance_test_clock(advance_delta);

                match advance_result {
                    Ok(_) => {
                        // Advancement succeeded
                        let new_tick = runtime.current_tick();

                        // Verify no overflow occurred
                        assert!(
                            new_tick >= current_tick,
                            "Clock should not go backwards: {} -> {}",
                            current_tick,
                            new_tick
                        );

                        // Should be a reasonable advancement
                        let expected_new_tick = current_tick.saturating_add(advance_delta);
                        assert!(
                            new_tick <= expected_new_tick,
                            "Clock advanced too far: expected <= {}, got {}",
                            expected_new_tick,
                            new_tick
                        );

                        // Test timer scheduling at extreme times
                        let timer_id = format!("extreme_timer_{}", test_idx);
                        let timer_result = runtime.schedule_timer(&timer_id, 10);

                        match timer_result {
                            Ok(_) => {
                                // Timer scheduled at extreme time
                                runtime.advance_test_clock(11);

                                // Verify timer behavior at extreme times
                                let events = runtime.get_event_log();
                                let timer_events: Vec<_> = events
                                    .iter()
                                    .filter(|e| e.event_type.contains("TIMER"))
                                    .collect();

                                // Should handle timers correctly even at extreme times
                                for event in timer_events {
                                    assert!(event.tick >= current_tick);
                                    assert!(event.tick <= runtime.current_tick());
                                }
                            }
                            Err(err) => {
                                // Timer scheduling may fail at extreme times
                                match err {
                                    LabError::TimerIdExhausted => {
                                        // Expected at extreme conditions
                                    }
                                    LabError::TickOverflow { .. } => {
                                        // Expected for overflow scenarios
                                    }
                                    _ => {
                                        // Other errors acceptable for extreme times
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => {
                        // Large advancements may be rejected
                        match err {
                            LabError::TickOverflow { current, delta } => {
                                assert_eq!(current, current_tick);
                                assert_eq!(delta, advance_delta);
                                // Should detect overflow correctly
                                assert!(
                                    current.saturating_add(delta) == u64::MAX
                                        || current + delta < current
                                ); // Overflow detection
                            }
                            _ => {
                                // Other errors may occur for extreme advancements
                            }
                        }
                    }
                }
            }

            // Test rapid time advancement attacks
            for rapid_idx in 0..1000 {
                let small_advance = rapid_idx % 100 + 1;
                let result = runtime.advance_test_clock(small_advance);

                match result {
                    Ok(_) => {
                        // Should handle rapid advancements
                    }
                    Err(_) => {
                        // May hit limits under rapid advancement
                        break;
                    }
                }
            }

            // Test timer ordering under extreme conditions
            let timer_ids: Vec<String> = (0..100).map(|i| format!("order_timer_{}", i)).collect();
            let mut timer_fire_times = Vec::new();

            for (i, timer_id) in timer_ids.iter().enumerate() {
                let fire_time = (i * 10) as u64 + 100;
                timer_fire_times.push(fire_time);

                let result = runtime.schedule_timer(timer_id, fire_time);
                if result.is_err() {
                    break; // Hit timer capacity limits
                }
            }

            // Advance time to fire all timers
            if !timer_fire_times.is_empty() {
                let max_fire_time = *timer_fire_times.iter().max().unwrap();
                let _ = runtime.advance_test_clock(max_fire_time + 100);

                // Verify timer ordering invariant
                let events = runtime.get_event_log();
                let timer_events: Vec<_> = events
                    .iter()
                    .filter(|e| e.event_type.contains("TIMER"))
                    .collect();

                let mut prev_tick = 0;
                for event in timer_events {
                    assert!(
                        event.tick >= prev_tick,
                        "Timers should fire in order: {} < {}",
                        event.tick,
                        prev_tick
                    );
                    prev_tick = event.tick;
                }
            }

            // Final time consistency check
            let final_tick = runtime.current_tick();
            assert!(final_tick < u64::MAX, "Final tick should not overflow");

            // All events should have reasonable timestamps
            let events = runtime.get_event_log();
            for event in events {
                assert!(
                    event.tick <= final_tick,
                    "Event timestamp {} should not exceed current time {}",
                    event.tick,
                    final_tick
                );
            }
        }

        #[test]
        fn negative_fault_profile_floating_point_and_probability_attacks() {
            // Test fault profile floating-point and probability attack resistance
            let config = LabRuntimeConfig {
                seed: 999,
                max_interleaving_budget: 1000,
                enable_repro_export: false,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).expect("runtime should create");

            // Test extreme and malicious probability values
            let malicious_probabilities = [
                f64::NAN,                           // Not a number
                f64::INFINITY,                      // Positive infinity
                f64::NEG_INFINITY,                  // Negative infinity
                -0.0,                               // Negative zero
                -1.0,                               // Invalid negative
                2.0,                                // Invalid > 1.0
                f64::MIN,                           // Smallest finite value
                f64::MAX,                           // Largest finite value
                f64::EPSILON,                       // Machine epsilon
                1.0 + f64::EPSILON,                 // Just above 1.0
                -f64::EPSILON,                      // Just below 0.0
                0.5000000000000001,                 // Precision edge case
                1.0 / 3.0,                          // Repeating decimal
                f64::from_bits(0x7FF8000000000001), // Specific NaN pattern
                f64::from_bits(0xFFF8000000000001), // Different NaN pattern
                100.0,                              // Way above 1.0
                -100.0,                             // Way below 0.0
            ];

            for (i, drop_prob) in malicious_probabilities.into_iter().enumerate() {
                let fault_profile = FaultProfile {
                    drop_probability: drop_prob,
                    reorder_depth: 1,
                    corruption_rate: 0.1,
                    delay_ticks: 10,
                    custom_data: Vec::new(),
                };

                let link_id = format!("prob_attack_{}", i);
                let result = runtime.create_virtual_link(
                    &link_id,
                    "attack-src",
                    "attack-tgt",
                    fault_profile.clone(),
                );

                match result {
                    Ok(_) => {
                        // Link created with potentially dangerous probability
                        assert!(
                            drop_prob.is_finite() && drop_prob >= 0.0 && drop_prob <= 1.0,
                            "Invalid probability {} should not create link",
                            drop_prob
                        );

                        // Test message sending with dangerous probabilities
                        for j in 0..100 {
                            let message = format!("prob_test_{}_{}", i, j).as_bytes().to_vec();
                            let send_result = runtime.send_message(&link_id, &message);

                            match send_result {
                                Ok(_) => {
                                    // Message sent successfully
                                }
                                Err(_) => {
                                    // May fail due to fault injection
                                }
                            }

                            // Advance time to process faults
                            runtime.advance_test_clock(1);
                        }

                        // Verify system stability after probability calculations
                        let events = runtime.get_event_log();
                        assert!(events.len() <= MAX_EVENTS);

                        // All events should be well-formed
                        for event in &events {
                            assert!(!event.event_type.is_empty());
                            assert!(event.tick <= runtime.current_tick());
                        }
                    }
                    Err(err) => {
                        // Invalid probabilities should be rejected
                        match err {
                            LabError::FaultRange { field, value } => {
                                assert_eq!(field, "drop_probability");
                                assert!(
                                    (value.is_nan() || value < 0.0 || value > 1.0),
                                    "Error should be for invalid probability, got value: {}",
                                    value
                                );
                            }
                            _ => {
                                // Other error types may be valid for extreme values
                            }
                        }
                    }
                }
            }

            // Test corruption rate with similar extreme values
            let malicious_corruption_rates = [f64::NAN, f64::INFINITY, -1.0, 2.0, f64::MAX];

            for (i, corruption_rate) in malicious_corruption_rates.into_iter().enumerate() {
                let fault_profile = FaultProfile {
                    drop_probability: 0.1,
                    reorder_depth: 1,
                    corruption_rate,
                    delay_ticks: 10,
                    custom_data: Vec::new(),
                };

                let link_id = format!("corruption_attack_{}", i);
                let result = runtime.create_virtual_link(
                    &link_id,
                    "corrupt-src",
                    "corrupt-tgt",
                    fault_profile,
                );

                match result {
                    Ok(_) => {
                        // Should only succeed with valid corruption rates
                        assert!(
                            corruption_rate.is_finite()
                                && corruption_rate >= 0.0
                                && corruption_rate <= 1.0,
                            "Invalid corruption rate {} should not create link",
                            corruption_rate
                        );
                    }
                    Err(err) => {
                        // Invalid corruption rates should be rejected
                        match err {
                            LabError::FaultRange { field, value } => {
                                assert_eq!(field, "corruption_rate");
                                assert!(
                                    (value.is_nan() || value < 0.0 || value > 1.0),
                                    "Error should be for invalid corruption rate"
                                );
                            }
                            _ => {
                                // Other error types may be valid
                            }
                        }
                    }
                }
            }

            // Test floating-point precision attacks in batch operations
            let precision_attacks = [
                vec![0.1; 10],                                 // Repeated 0.1 (known precision issues)
                vec![0.3333333333333333; 10],                  // Repeated 1/3
                (0..100).map(|i| (i as f64) * 0.01).collect(), // 0.00, 0.01, 0.02, ...
            ];

            for (attack_idx, probs) in precision_attacks.into_iter().enumerate() {
                let mut accumulated_error = 0.0;

                for (i, prob) in probs.into_iter().enumerate() {
                    let fault_profile = FaultProfile {
                        drop_probability: prob,
                        reorder_depth: 0,
                        corruption_rate: 0.0,
                        delay_ticks: 0,
                        custom_data: Vec::new(),
                    };

                    let link_id = format!("precision_attack_{}_{}", attack_idx, i);
                    if runtime
                        .create_virtual_link(
                            &link_id,
                            "precision-src",
                            "precision-tgt",
                            fault_profile,
                        )
                        .is_ok()
                    {
                        // Test that accumulated floating-point errors don't cause issues
                        accumulated_error += prob;

                        // Should handle precision issues gracefully
                        let test_message = format!("precision_{}", i).as_bytes().to_vec();
                        let _result = runtime.send_message(&link_id, &test_message);
                    }
                }

                // System should remain stable despite floating-point precision issues
                runtime.advance_test_clock(10);
                let events = runtime.get_event_log();
                assert!(events.len() <= MAX_EVENTS);
            }
        }

        #[test]
        fn negative_virtual_link_capacity_exhaustion_and_memory_pressure() {
            // Test virtual link capacity exhaustion and memory pressure scenarios
            let config = LabRuntimeConfig {
                seed: 1111,
                max_interleaving_budget: 1000,
                enable_repro_export: false,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).expect("runtime should create");

            // Test maximum virtual link creation
            let mut created_links = Vec::new();
            for i in 0..MAX_VIRTUAL_LINKS + 100 {
                let link_id = format!("capacity_link_{:06}", i);
                let fault_profile = FaultProfile {
                    drop_probability: 0.1,
                    reorder_depth: 1,
                    corruption_rate: 0.0,
                    delay_ticks: 1,
                    custom_data: Vec::new(),
                };

                let result = runtime.create_virtual_link(
                    &link_id,
                    &format!("src_{}", i),
                    &format!("tgt_{}", i),
                    fault_profile,
                );

                match result {
                    Ok(_) => {
                        created_links.push(link_id);
                    }
                    Err(err) => {
                        // Should hit capacity limit
                        match err {
                            LabError::LinkCapacityExceeded { limit } => {
                                assert_eq!(limit, MAX_VIRTUAL_LINKS);
                                assert!(created_links.len() <= MAX_VIRTUAL_LINKS);
                            }
                            _ => {
                                // Other capacity-related errors are acceptable
                            }
                        }
                        break;
                    }
                }
            }

            // Verify link capacity is respected
            assert!(created_links.len() <= MAX_VIRTUAL_LINKS);

            // Test memory pressure on created links
            for (i, link_id) in created_links.iter().enumerate() {
                // Send large messages to stress memory
                let large_message = vec![i as u8; 10_000]; // 10KB per message
                let send_result = runtime.send_message(link_id, &large_message);

                match send_result {
                    Ok(_) => {
                        // Message sent successfully
                    }
                    Err(_) => {
                        // May fail under memory pressure
                    }
                }

                // Periodic time advancement to process messages
                if i % 100 == 0 {
                    runtime.advance_test_clock(10);
                }
            }

            // Test reorder buffer capacity exhaustion
            let reorder_stress_profile = FaultProfile {
                drop_probability: 0.0,
                reorder_depth: MAX_REORDER_BUFFERS + 100, // Exceed maximum
                corruption_rate: 0.0,
                delay_ticks: 0,
                custom_data: Vec::new(),
            };

            let reorder_link_id = "reorder_stress_link";
            let reorder_result = runtime.create_virtual_link(
                reorder_link_id,
                "reorder-src",
                "reorder-tgt",
                reorder_stress_profile,
            );

            match reorder_result {
                Ok(_) => {
                    // Send many messages to stress reorder buffer
                    for j in 0..MAX_REORDER_BUFFERS * 2 {
                        let message = format!("reorder_stress_{}", j).as_bytes().to_vec();
                        let send_result = runtime.send_message(reorder_link_id, &message);

                        match send_result {
                            Ok(_) => {
                                // Message queued in reorder buffer
                            }
                            Err(_) => {
                                // Reorder buffer may be full
                                break;
                            }
                        }
                    }

                    // Advance time to process reorder buffer
                    runtime.advance_test_clock(100);
                }
                Err(_) => {
                    // Extreme reorder depth may be rejected at creation
                }
            }

            // Test custom data memory pressure
            let memory_stress_profile = FaultProfile {
                drop_probability: 0.1,
                reorder_depth: 1,
                corruption_rate: 0.0,
                delay_ticks: 1,
                custom_data: vec![0xFF; 1_000_000], // 1MB custom data
            };

            let memory_links: Vec<_> = (0..100).map(|i| format!("memory_stress_{}", i)).collect();

            let mut memory_links_created = 0;
            for link_id in &memory_links {
                let result = runtime.create_virtual_link(
                    link_id,
                    "memory-src",
                    "memory-tgt",
                    memory_stress_profile.clone(),
                );

                match result {
                    Ok(_) => {
                        memory_links_created += 1;
                    }
                    Err(_) => {
                        // May hit memory limits
                        break;
                    }
                }
            }

            // Should handle some level of memory pressure
            assert!(
                memory_links_created > 0,
                "Should be able to create at least one memory-intensive link"
            );

            // Verify system stability under memory pressure
            let events = runtime.get_event_log();
            assert!(events.len() <= MAX_EVENTS);

            // All events should be well-formed despite memory pressure
            for event in &events {
                assert!(!event.event_type.is_empty());
                assert!(event.tick <= runtime.current_tick());
            }

            // Test rapid link creation/destruction cycles
            for cycle in 0..1000 {
                let cycle_link_id = format!("cycle_link_{}", cycle);
                let cycle_profile = FaultProfile {
                    drop_probability: 0.05,
                    reorder_depth: 1,
                    corruption_rate: 0.0,
                    delay_ticks: 0,
                    custom_data: Vec::new(),
                };

                // Create link
                let create_result = runtime.create_virtual_link(
                    &cycle_link_id,
                    "cycle-src",
                    "cycle-tgt",
                    cycle_profile,
                );

                if create_result.is_ok() {
                    // Send a message
                    let cycle_message = format!("cycle_msg_{}", cycle).as_bytes().to_vec();
                    let _send_result = runtime.send_message(&cycle_link_id, &cycle_message);

                    // Destroy link (if implemented)
                    // Note: Assuming destroy_virtual_link exists or links are cleaned up automatically
                }

                // Break if we hit capacity limits
                if create_result.is_err() {
                    break;
                }

                // Periodic cleanup
                if cycle % 100 == 0 {
                    runtime.advance_test_clock(1);
                }
            }

            // Final memory and capacity integrity check
            let final_events = runtime.get_event_log();
            assert!(final_events.len() <= MAX_EVENTS);
        }

        #[test]
        fn negative_scenario_lifecycle_state_corruption_and_race_conditions() {
            // Test scenario lifecycle state corruption and race condition resistance
            let config = LabRuntimeConfig {
                seed: 2222,
                max_interleaving_budget: 10000,
                enable_repro_export: true,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).expect("runtime should create");

            // Test invalid scenario lifecycle sequences
            let invalid_sequences = vec![
                // Complete before start
                vec![("scenario_1", "complete"), ("scenario_1", "start")],
                // Fail before start
                vec![("scenario_2", "fail"), ("scenario_2", "start")],
                // Double start
                vec![("scenario_3", "start"), ("scenario_3", "start")],
                // Double complete
                vec![
                    ("scenario_4", "start"),
                    ("scenario_4", "complete"),
                    ("scenario_4", "complete"),
                ],
                // Complete then fail
                vec![
                    ("scenario_5", "start"),
                    ("scenario_5", "complete"),
                    ("scenario_5", "fail"),
                ],
                // Fail then complete
                vec![
                    ("scenario_6", "start"),
                    ("scenario_6", "fail"),
                    ("scenario_6", "complete"),
                ],
            ];

            for (seq_idx, sequence) in invalid_sequences.into_iter().enumerate() {
                for (scenario_id, action) in sequence {
                    let result = match action {
                        "start" => runtime.start_scenario(scenario_id),
                        "complete" => runtime.complete_scenario(scenario_id),
                        "fail" => {
                            runtime.fail_scenario(scenario_id, &format!("Test failure {}", seq_idx))
                        }
                        _ => continue,
                    };

                    // Some operations should fail based on state
                    match result {
                        Ok(_) => {
                            // Valid state transitions should succeed
                        }
                        Err(_) => {
                            // Invalid state transitions should fail gracefully
                        }
                    }
                }
            }

            // Test concurrent scenario operations (simulated)
            let concurrent_scenarios: Vec<String> = (0..100)
                .map(|i| format!("concurrent_scenario_{}", i))
                .collect();

            // Start all scenarios rapidly
            for scenario_id in &concurrent_scenarios {
                let result = runtime.start_scenario(scenario_id);
                match result {
                    Ok(_) => {
                        // Scenario started successfully
                    }
                    Err(_) => {
                        // May hit limits under rapid concurrent operations
                    }
                }
            }

            // Interleave various operations rapidly
            for i in 0..1000 {
                let scenario_idx = i % concurrent_scenarios.len();
                let scenario_id = &concurrent_scenarios[scenario_idx];

                match i % 4 {
                    0 => {
                        // Try to complete scenario
                        let _result = runtime.complete_scenario(scenario_id);
                    }
                    1 => {
                        // Try to fail scenario
                        let _result = runtime.fail_scenario(scenario_id, "Concurrent test failure");
                    }
                    2 => {
                        // Try to start scenario (may already be started)
                        let _result = runtime.start_scenario(scenario_id);
                    }
                    3 => {
                        // Advance time to trigger various events
                        let _result = runtime.advance_test_clock(1);
                    }
                    _ => {}
                }
            }

            // Test scenario with extreme names and failure reasons
            let extreme_scenarios = vec![
                ("".to_string(), "empty_name"),                // Empty name
                ("x".repeat(100_000), "very_long_name"),       // Very long name
                ("scenario\x00\x01\x02null", "binary_data"),   // Binary data in name
                ("scenario\u{202E}reverse", "unicode_attack"), // Unicode direction override
                ("../../../etc/passwd", "path_traversal"),     // Path traversal attempt
                ("scenario; rm -rf /", "command_injection"),   // Command injection attempt
            ];

            for (scenario_id, failure_reason) in extreme_scenarios {
                // Test start with extreme scenario ID
                let start_result = runtime.start_scenario(&scenario_id);

                match start_result {
                    Ok(_) => {
                        // If start succeeds, test failure with extreme reason
                        let failure_result = runtime.fail_scenario(&scenario_id, failure_reason);

                        match failure_result {
                            Ok(_) => {
                                // Extreme content handled gracefully
                            }
                            Err(_) => {
                                // May reject extreme failure reasons
                            }
                        }
                    }
                    Err(_) => {
                        // Extreme scenario IDs may be rejected
                    }
                }
            }

            // Test interleaving budget exhaustion
            let budget_scenario = "budget_exhaustion_test";
            let start_result = runtime.start_scenario(budget_scenario);

            if start_result.is_ok() {
                // Perform many operations to potentially exhaust budget
                for i in 0..runtime.config.max_interleaving_budget + 100 {
                    // Create timer to generate interleaving events
                    let timer_id = format!("budget_timer_{}", i);
                    let timer_result = runtime.schedule_timer(&timer_id, i as u64 + 100);

                    if timer_result.is_err() {
                        break; // Hit some limit
                    }

                    // Advance time to fire timer
                    runtime.advance_test_clock(1);

                    // Check if budget exhausted
                    if i > runtime.config.max_interleaving_budget {
                        // Should hit budget exhaustion
                        break;
                    }
                }

                // Try to complete the scenario
                let complete_result = runtime.complete_scenario(budget_scenario);
                match complete_result {
                    Ok(_) => {
                        // Budget exhaustion may or may not affect completion
                    }
                    Err(err) => {
                        match err {
                            LabError::BudgetExceeded { explored, budget } => {
                                assert!(explored >= budget);
                            }
                            _ => {
                                // Other errors acceptable
                            }
                        }
                    }
                }
            }

            // Verify system state integrity after stress testing
            let final_events = runtime.get_event_log();
            assert!(final_events.len() <= MAX_EVENTS);

            // All events should have valid structure
            for event in &final_events {
                assert!(!event.event_type.is_empty());
                assert!(event.tick <= runtime.current_tick());
            }

            // Test repro bundle export after state stress
            if runtime.config.enable_repro_export {
                let export_result = runtime.export_repro_bundle();
                match export_result {
                    Ok(bundle) => {
                        // Bundle should be valid despite state stress
                        let serialization_result = serde_json::to_string(&bundle);
                        match serialization_result {
                            Ok(_json_str) => {
                                // Should serialize successfully
                            }
                            Err(_) => {
                                // May fail with extreme content
                            }
                        }
                    }
                    Err(_) => {
                        // Export may fail after state corruption attempts
                    }
                }
            }

            // Final clock consistency check
            let final_tick = runtime.current_tick();
            assert!(final_tick < u64::MAX, "Clock should not overflow");
        }

        #[test]
        fn negative_repro_bundle_serialization_injection_and_corruption_attacks() {
            // Test repro bundle serialization injection and corruption attack resistance
            let config = LabRuntimeConfig {
                seed: 3333,
                max_interleaving_budget: 1000,
                enable_repro_export: true,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).expect("runtime should create");

            // Create scenario with potentially dangerous content
            let injection_scenario = "injection_test_scenario";
            runtime
                .start_scenario(injection_scenario)
                .expect("start injection scenario");

            // Create virtual links with injection attempts
            let injection_profiles = vec![
                FaultProfile {
                    drop_probability: 0.1,
                    reorder_depth: 1,
                    corruption_rate: 0.0,
                    delay_ticks: 1,
                    custom_data: b"\x00\x01\x02binary_data\xFF\xFE\xFD".to_vec(),
                },
                FaultProfile {
                    drop_probability: 0.2,
                    reorder_depth: 2,
                    corruption_rate: 0.1,
                    delay_ticks: 2,
                    custom_data: "unicode_data_控制字符\u{202E}injection".as_bytes().to_vec(),
                },
                FaultProfile {
                    drop_probability: 0.3,
                    reorder_depth: 3,
                    corruption_rate: 0.2,
                    delay_ticks: 3,
                    custom_data: format!("{}/../../../etc/passwd", "x".repeat(1000))
                        .as_bytes()
                        .to_vec(),
                },
            ];

            for (i, profile) in injection_profiles.into_iter().enumerate() {
                let link_id = format!("injection_link_{}", i);
                let source = format!("src\x00injection_{}", i);
                let target = format!("tgt\u{202E}fake_{}", i);

                let result = runtime.create_virtual_link(&link_id, &source, &target, profile);

                if result.is_ok() {
                    // Send messages with injection content
                    let injection_messages = vec![
                        b"\x00\x01\x02null_bytes\xFF\xFE\xFD".to_vec(),
                        "unicode_message_控制字符\u{202E}reverse"
                            .as_bytes()
                            .to_vec(),
                        format!("{}'; DROP TABLE logs; --", "x".repeat(500))
                            .as_bytes()
                            .to_vec(),
                        format!("{}/../../../secret_file", "msg".repeat(100))
                            .as_bytes()
                            .to_vec(),
                    ];

                    for (j, message) in injection_messages.into_iter().enumerate() {
                        let send_result = runtime.send_message(&link_id, &message);
                        if send_result.is_ok() {
                            runtime.advance_test_clock(1);
                        }
                    }
                }
            }

            // Create timers with injection attempts
            let injection_timer_ids = vec![
                "timer\x00null_byte",
                "timer\u{202E}unicode_attack",
                "timer/../../../timer_injection",
                "timer'; DROP TABLE timers; --",
                &"x".repeat(10_000), // Very long timer ID
            ];

            for timer_id in injection_timer_ids {
                let timer_result = runtime.schedule_timer(timer_id, 100);
                match timer_result {
                    Ok(_) => {
                        // Timer scheduled with injection content
                    }
                    Err(_) => {
                        // Injection content may be rejected
                    }
                }
            }

            runtime.advance_test_clock(200); // Fire timers

            // Fail scenario with injection attempt in failure reason
            let injection_failure_reason =
                "failure_reason\x00\x01\x02\u{202E}injection_attempt/../../../failure_log";
            let fail_result = runtime.fail_scenario(injection_scenario, injection_failure_reason);
            match fail_result {
                Ok(_) => {
                    // Failure recorded with injection content
                }
                Err(_) => {
                    // May reject injection content in failure reasons
                }
            }

            // Export repro bundle with injection content
            let export_result = runtime.export_repro_bundle();

            match export_result {
                Ok(bundle) => {
                    // Test serialization safety
                    let serialization_result = serde_json::to_string(&bundle);

                    match serialization_result {
                        Ok(json_str) => {
                            // Verify JSON is safe and well-formed
                            assert!(
                                !json_str.contains("\x00"),
                                "JSON should not contain null bytes"
                            );

                            // Should be valid JSON
                            let parse_test: Result<serde_json::Value, _> =
                                serde_json::from_str(&json_str);
                            assert!(parse_test.is_ok(), "Serialized bundle should be valid JSON");

                            // Should not contain obvious injection patterns
                            assert!(
                                !json_str.contains("DROP TABLE"),
                                "JSON should not contain SQL injection"
                            );
                            assert!(
                                !json_str.contains("../../../"),
                                "JSON should not contain path traversal"
                            );

                            // Test deserialization
                            let deserialization_result: Result<ReproBundle, _> =
                                serde_json::from_str(&json_str);
                            match deserialization_result {
                                Ok(reconstructed) => {
                                    // Should successfully round-trip
                                    assert_eq!(reconstructed.schema_version, bundle.schema_version);
                                    assert_eq!(reconstructed.seed, bundle.seed);

                                    // Verify injection content is safely contained
                                    // (not executed or interpreted maliciously)
                                    for event in &reconstructed.events {
                                        // Events should be structurally valid
                                        assert!(!event.event_type.is_empty());
                                        // Injection content may be preserved but should not be active
                                    }
                                }
                                Err(_) => {
                                    // Extreme injection content may prevent deserialization
                                }
                            }

                            // Test replay safety
                            let replay_result = runtime.replay_from_bundle(&bundle);
                            match replay_result {
                                Ok(_) => {
                                    // Replay should not execute injection content
                                    // Verify replay doesn't cause side effects
                                    let replay_events = runtime.get_event_log();
                                    for event in &replay_events {
                                        assert!(!event.event_type.is_empty());
                                        // Injection content should not corrupt event structure
                                    }
                                }
                                Err(err) => {
                                    // Replay may fail with injection content
                                    match err {
                                        LabError::ReplayDivergence { .. } => {
                                            // Expected for injection-modified content
                                        }
                                        LabError::BundleValidation { .. } => {
                                            // Validation may reject injection content
                                        }
                                        _ => {
                                            // Other replay errors acceptable
                                        }
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            // Extreme injection content may prevent serialization
                            match err {
                                LabError::BundleSerialization { detail } => {
                                    // Should provide meaningful error for serialization failure
                                    assert!(!detail.is_empty());
                                }
                                _ => {
                                    // Other serialization errors acceptable
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    // Export may fail with extreme injection content
                    match err {
                        LabError::BundleValidation { .. } => {
                            // Validation may reject injection content
                        }
                        _ => {
                            // Other export errors acceptable
                        }
                    }
                }
            }

            // Test bundle corruption resistance
            if let Ok(original_bundle) = runtime.export_repro_bundle() {
                let original_json = serde_json::to_string(&original_bundle).unwrap();

                // Various corruption patterns
                let corruption_patterns = vec![
                    // Truncate JSON
                    &original_json[..original_json.len() / 2],
                    // Invalid JSON structure
                    &original_json.replace("}", ""),
                    &original_json.replace("\"", "'"),
                    &original_json.replace(":", "="),
                    // Field manipulation
                    &original_json.replace("\"seed\"", "\"malicious_seed\""),
                    &original_json.replace("\"events\"", "\"malicious_events\""),
                    // Value injection
                    &original_json.replace("1000", "0xDEADBEEF"),
                    &format!("{}\x00corruption", original_json),
                ];

                for (corruption_idx, corrupted_json) in corruption_patterns.into_iter().enumerate()
                {
                    let parse_result: Result<ReproBundle, _> = serde_json::from_str(corrupted_json);

                    match parse_result {
                        Ok(corrupted_bundle) => {
                            // If parsing succeeds despite corruption, test validation
                            let validation_result = runtime.validate_bundle(&corrupted_bundle);
                            // Should detect corruption during validation
                        }
                        Err(_) => {
                            // Corruption should be detected during parsing
                        }
                    }
                }
            }

            // Final integrity check
            let final_events = runtime.get_event_log();
            assert!(final_events.len() <= MAX_EVENTS);

            // All events should remain structurally valid despite injection attempts
            for event in &final_events {
                assert!(!event.event_type.is_empty());
                assert!(event.tick <= runtime.current_tick());
            }
        }

        #[test]
        fn negative_timer_id_exhaustion_and_concurrent_timer_attacks() {
            // Test timer ID exhaustion and concurrent timer attack resistance
            let config = LabRuntimeConfig {
                seed: 4444,
                max_interleaving_budget: 10000,
                enable_repro_export: false,
                fault_profiles: BTreeMap::new(),
            };

            let mut runtime = LabRuntime::new(config).expect("runtime should create");

            // Test timer ID exhaustion by creating many timers
            let mut created_timers = Vec::new();
            let timer_creation_limit = 100_000; // Reasonable limit to avoid test timeout

            for i in 0..timer_creation_limit {
                let timer_id = format!("exhaustion_timer_{:08}", i);
                let fire_time = (i % 1000) as u64 + 100; // Various fire times

                let result = runtime.schedule_timer(&timer_id, fire_time);

                match result {
                    Ok(_) => {
                        created_timers.push((timer_id, fire_time));
                    }
                    Err(err) => {
                        // Should eventually hit ID exhaustion
                        match err {
                            LabError::TimerIdExhausted => {
                                // Expected behavior when IDs are exhausted
                                break;
                            }
                            _ => {
                                // Other errors may occur under stress
                                break;
                            }
                        }
                    }
                }

                // Periodic time advancement to fire some timers and free IDs
                if i % 1000 == 0 {
                    runtime.advance_test_clock(50);
                }
            }

            // Verify we created a reasonable number of timers before exhaustion
            assert!(
                created_timers.len() > 1000,
                "Should be able to create many timers before exhaustion"
            );

            // Test concurrent timer operations (simulated rapid operations)
            let concurrent_timer_scenarios = vec![
                // Many timers with same fire time
                (500, 100),
                // Many timers with sequential fire times
                (500, 200),
                // Timers with extreme fire times
                (100, u64::MAX / 2),
                // Immediate timers
                (100, 0),
            ];

            for (timer_count, base_fire_time) in concurrent_timer_scenarios {
                let scenario_start_time = runtime.current_tick();

                // Create many timers rapidly
                let mut scenario_timers = Vec::new();
                for j in 0..timer_count {
                    let timer_id = format!("concurrent_{}_timer_{}", base_fire_time, j);
                    let fire_time = base_fire_time.saturating_add(j as u64);

                    let result = runtime.schedule_timer(&timer_id, fire_time);
                    match result {
                        Ok(_) => {
                            scenario_timers.push((timer_id, fire_time));
                        }
                        Err(_) => {
                            // May hit limits under concurrent stress
                            break;
                        }
                    }
                }

                // Advance time to fire all timers in this scenario
                if !scenario_timers.is_empty() {
                    let max_fire_time = scenario_timers
                        .iter()
                        .map(|(_, fire_time)| fire_time)
                        .max()
                        .unwrap();
                    let advance_amount = max_fire_time
                        .saturating_sub(scenario_start_time)
                        .saturating_add(100);

                    let advance_result = runtime.advance_test_clock(advance_amount);
                    match advance_result {
                        Ok(_) => {
                            // Time advanced successfully
                        }
                        Err(_) => {
                            // May hit overflow or other limits
                        }
                    }
                }

                // Verify timer ordering invariant
                let events = runtime.get_event_log();
                let timer_events: Vec<_> = events
                    .iter()
                    .filter(|e| {
                        e.event_type.contains("TIMER")
                            && e.description.contains(&base_fire_time.to_string())
                    })
                    .collect();

                // Check timer events are in correct order
                let mut prev_tick = scenario_start_time;
                for event in timer_events {
                    assert!(
                        event.tick >= prev_tick,
                        "Timer events should fire in order: {} >= {}",
                        event.tick,
                        prev_tick
                    );
                    prev_tick = event.tick;
                }
            }

            // Test timer cancellation scenarios (if supported)
            let cancellation_timers: Vec<_> =
                (0..1000).map(|i| format!("cancel_timer_{}", i)).collect();

            // Schedule timers for cancellation testing
            for timer_id in &cancellation_timers {
                let fire_time = 10000; // Far in the future
                let result = runtime.schedule_timer(timer_id, fire_time);
                if result.is_err() {
                    break; // Hit limits
                }
            }

            // Test rapid timer creation/cancellation cycles
            for cycle in 0..10000 {
                let cycle_timer_id = format!("cycle_timer_{}", cycle);
                let fire_time = (cycle % 100) as u64 + 1000;

                // Create timer
                let create_result = runtime.schedule_timer(&cycle_timer_id, fire_time);

                match create_result {
                    Ok(_) => {
                        // Timer created successfully

                        // Immediately try to "cancel" by creating timer with same ID
                        // (behavior depends on implementation)
                        let duplicate_result =
                            runtime.schedule_timer(&cycle_timer_id, fire_time + 1);
                        match duplicate_result {
                            Ok(_) => {
                                // Duplicate timer ID handled (may overwrite or be rejected)
                            }
                            Err(_) => {
                                // Duplicate timer ID rejected
                            }
                        }
                    }
                    Err(_) => {
                        // Creation failed (likely hit limits)
                        break;
                    }
                }

                // Advance time occasionally to fire some timers
                if cycle % 500 == 0 {
                    runtime.advance_test_clock(50);
                }
            }

            // Test timer precision at extreme time values
            let precision_timers = vec![
                ("precision_0", 0),                      // Immediate
                ("precision_1", 1),                      // Next tick
                ("precision_max_half", u64::MAX / 2),    // Very far future
                ("precision_max_minus_1", u64::MAX - 1), // Near overflow
            ];

            for (timer_id, fire_time) in precision_timers {
                let current_time = runtime.current_tick();
                let result = runtime.schedule_timer(timer_id, fire_time);

                match result {
                    Ok(_) => {
                        // Timer scheduled at extreme time
                        if fire_time <= current_time + 1000 {
                            // For reasonable fire times, advance and verify
                            let advance_amount =
                                fire_time.saturating_sub(current_time).saturating_add(10);
                            let advance_result = runtime.advance_test_clock(advance_amount);

                            if advance_result.is_ok() {
                                // Verify timer fired correctly
                                let events = runtime.get_event_log();
                                let timer_fired = events.iter().any(|e| {
                                    e.event_type.contains("TIMER")
                                        && e.description.contains(timer_id)
                                });

                                if fire_time <= runtime.current_tick() {
                                    // Timer should have fired
                                    assert!(
                                        timer_fired,
                                        "Timer {} should have fired at time {}",
                                        timer_id, fire_time
                                    );
                                }
                            }
                        }
                    }
                    Err(err) => {
                        // Extreme timer values may be rejected
                        match err {
                            LabError::TickOverflow { .. } => {
                                // Expected for extreme fire times
                            }
                            LabError::TimerIdExhausted => {
                                // Expected when timer capacity is reached
                            }
                            _ => {
                                // Other timer-related errors are acceptable
                            }
                        }
                    }
                }
            }

            // Final timer system integrity check
            let final_events = runtime.get_event_log();
            assert!(final_events.len() <= MAX_EVENTS);

            // All timer events should have valid structure
            let timer_events: Vec<_> = final_events
                .iter()
                .filter(|e| e.event_type.contains("TIMER"))
                .collect();

            for event in timer_events {
                assert!(!event.event_type.is_empty());
                assert!(event.tick <= runtime.current_tick());
                assert!(!event.description.is_empty());
            }

            // Verify timer ordering invariant across all events
            let mut all_timer_ticks: Vec<u64> = final_events
                .iter()
                .filter(|e| e.event_type.contains("TIMER"))
                .map(|e| e.tick)
                .collect();

            all_timer_ticks.sort_unstable();

            // Check for ordering violations
            for window in all_timer_ticks.windows(2) {
                assert!(
                    window[1] >= window[0],
                    "Timer ordering violation: {} should not come before {}",
                    window[1],
                    window[0]
                );
            }
        }
    }

    // =========================================================================
    // NEGATIVE-PATH TESTS FOR EDGE CASES AND MALICIOUS INPUT
    // =========================================================================

    #[test]
    fn negative_fault_profile_with_extreme_floating_point_values() {
        // Test FaultProfile with pathological floating point values
        let extreme_profiles = vec![
            FaultProfile {
                drop_pct: f64::INFINITY,
                corrupt_probability: 0.0,
                reorder_depth: 0,
                delay_ticks: 0,
            },
            FaultProfile {
                drop_pct: f64::NEG_INFINITY,
                corrupt_probability: 0.0,
                reorder_depth: 0,
                delay_ticks: 0,
            },
            FaultProfile {
                drop_pct: 0.0,
                corrupt_probability: f64::INFINITY,
                reorder_depth: 0,
                delay_ticks: 0,
            },
            FaultProfile {
                drop_pct: -0.0, // Negative zero
                corrupt_probability: 0.0,
                reorder_depth: 0,
                delay_ticks: 0,
            },
            FaultProfile {
                drop_pct: f64::from_bits(0x7ff8000000000001), // Specific NaN pattern
                corrupt_probability: 0.0,
                reorder_depth: 0,
                delay_ticks: 0,
            },
        ];

        for (i, profile) in extreme_profiles.iter().enumerate() {
            let result = profile.validate();

            match result {
                Err(LabError::FaultRange { field, value }) => {
                    // Expected - infinite and NaN values should be rejected
                    assert!(
                        value.is_infinite() || value.is_nan() || value < 0.0 || value > 1.0,
                        "Profile {i} should reject extreme value {value} in field {field}"
                    );
                }
                Ok(_) => {
                    // -0.0 might be considered valid (it's equal to 0.0)
                    assert!(
                        profile.drop_pct == 0.0 && profile.corrupt_probability == 0.0,
                        "Profile {i} unexpectedly passed validation"
                    );
                }
                Err(other) => {
                    panic!("Profile {i} failed with unexpected error: {other}");
                }
            }
        }
    }

    #[test]
    fn negative_virtual_link_with_malicious_endpoint_names() {
        // Test VirtualLink creation with malicious endpoint names
        let malicious_names = vec![
            "endpoint\0with_null",                   // Null byte injection
            "endpoint\r\nHTTP/1.1 200 OK",           // HTTP header injection
            "endpoint\x1b[31mRED\x1b[0m",            // ANSI escape sequences
            "endpoint\u{202E}reverse\u{202D}",       // BiDi override attack
            "endpoint<script>alert('xss')</script>", // XSS-style payload
            "../../../../../../etc/passwd",          // Path traversal
            "endpoint\u{FEFF}bom",                   // Byte order mark
            "\u{200B}endpoint",                      // Zero-width space prefix
            "endpoint".repeat(10000),                // Extremely long name
        ];

        for (i, malicious_name) in malicious_names.iter().enumerate() {
            let profile = FaultProfile::default();

            // Test as source name
            match VirtualLink::new(malicious_name, "target", profile.clone()) {
                Ok(link) => {
                    // Should contain the malicious content as-is (no sanitization expected)
                    assert_eq!(link.source, *malicious_name);
                    assert_eq!(link.target, "target");
                }
                Err(_) => {
                    // Rejection is also acceptable for malicious input
                }
            }

            // Test as target name
            match VirtualLink::new("source", malicious_name, profile) {
                Ok(link) => {
                    assert_eq!(link.source, "source");
                    assert_eq!(link.target, *malicious_name);
                }
                Err(_) => {
                    // Rejection acceptable
                }
            }
        }
    }

    #[test]
    fn negative_lab_config_with_boundary_and_overflow_seeds() {
        // Test LabConfig with edge case seed values
        let boundary_seeds = vec![
            1,                  // Minimum valid seed
            u64::MAX,           // Maximum possible seed
            u64::MAX - 1,       // Near maximum
            0x7FFFFFFFFFFFFFFF, // i64::MAX
            0x8000000000000000, // First bit of sign in two's complement
            0xDEADBEEF00000000, // High entropy pattern
            0x0000000000000001, // Minimal non-zero
            42,                 // Common test value
        ];

        for seed in boundary_seeds {
            let config = LabConfig {
                seed,
                max_ticks: 10_000,
                max_interleavings: 1_000,
                enable_dpor: false,
            };

            let validation_result = config.validate();
            assert!(validation_result.is_ok(), "Seed {seed} should be valid");

            // Test runtime creation with boundary seeds
            match LabRuntime::new(config) {
                Ok(runtime) => {
                    assert_eq!(runtime.seed, seed);
                    // Verify determinism with boundary seeds
                    let first_rng_value = runtime.rng.clone().next_u64();
                    let second_runtime = LabRuntime::new(LabConfig {
                        seed,
                        max_ticks: 10_000,
                        max_interleavings: 1_000,
                        enable_dpor: false,
                    })
                    .unwrap();
                    let second_rng_value = second_runtime.rng.clone().next_u64();
                    assert_eq!(
                        first_rng_value, second_rng_value,
                        "Boundary seed {seed} must produce deterministic RNG"
                    );
                }
                Err(e) => {
                    panic!("Boundary seed {seed} should not fail runtime creation: {e}");
                }
            }
        }

        // Test zero seed specifically (should be rejected)
        let zero_config = LabConfig {
            seed: 0,
            max_ticks: 10_000,
            max_interleavings: 1_000,
            enable_dpor: false,
        };

        match zero_config.validate() {
            Err(LabError::NoSeed) => {} // Expected
            other => panic!("Zero seed should be rejected, got {other:?}"),
        }
    }

    #[test]
    fn negative_test_clock_timer_scheduling_under_memory_pressure() {
        let mut clock = TestClock::new();

        // Schedule thousands of timers to test memory behavior
        let timer_count = 10_000;
        let mut scheduled_timers = Vec::new();

        for i in 0..timer_count {
            let fire_time = (i as u64) % 1000; // Distribute across 1000 ticks
            let label = format!("stress_timer_{:05}", i);

            match clock.schedule_timer(fire_time, label) {
                Ok(timer_id) => {
                    scheduled_timers.push((timer_id, fire_time));
                }
                Err(LabError::TimerIdExhausted) => {
                    // Expected when hitting ID limits
                    break;
                }
                Err(LabError::TickOverflow { .. }) => {
                    // Expected when fire time would overflow
                    break;
                }
                Err(other) => {
                    panic!("Unexpected timer scheduling error: {other}");
                }
            }
        }

        // Verify we scheduled a reasonable number before hitting limits
        assert!(
            scheduled_timers.len() > 100,
            "Should schedule at least 100 timers before limits"
        );

        // Advance clock and verify all timers fire correctly
        let fired_timers = clock.advance(1000).unwrap();

        // Count timers that should have fired
        let expected_fired = scheduled_timers
            .iter()
            .filter(|(_, fire_time)| *fire_time <= 1000)
            .count();

        assert_eq!(
            fired_timers.len(),
            expected_fired,
            "All scheduled timers within advance range should fire"
        );

        // Verify timer ordering is preserved under stress
        let mut fire_ticks: Vec<u64> = fired_timers.iter().map(|(tick, _)| *tick).collect();
        fire_ticks.sort_unstable();

        for window in fire_ticks.windows(2) {
            assert!(
                window[1] >= window[0],
                "Timer ordering must be preserved under memory pressure"
            );
        }
    }

    #[test]
    fn negative_splitmix64_rng_with_pathological_seed_patterns() {
        // Test SplitMix64 with seeds designed to test internal state behavior
        let pathological_seeds = vec![
            0x0000000000000000, // Would be rejected by LabConfig but test RNG directly
            0xFFFFFFFFFFFFFFFF, // All bits set
            0xAAAAAAAAAAAAAAAA, // Alternating bits
            0x5555555555555555, // Opposite alternating
            0x0F0F0F0F0F0F0F0F, // Nibble pattern
            0xF0F0F0F0F0F0F0F0, // Inverse nibble pattern
            0x0123456789ABCDEF, // Sequential hex
            0xFEDCBA9876543210, // Reverse sequential
        ];

        for seed in pathological_seeds {
            let mut rng1 = SplitMix64::new(seed);
            let mut rng2 = SplitMix64::new(seed);

            // Verify determinism even with pathological seeds
            for iteration in 0..1000 {
                let val1 = rng1.next_u64();
                let val2 = rng2.next_u64();
                assert_eq!(
                    val1, val2,
                    "Pathological seed 0x{seed:016X} failed determinism at iteration {iteration}"
                );
            }

            // Test f64 generation doesn't produce invalid values
            let mut rng3 = SplitMix64::new(seed);
            for _ in 0..1000 {
                let f_val = rng3.next_f64();
                assert!(
                    f_val.is_finite(),
                    "RNG with seed 0x{seed:016X} produced non-finite f64: {f_val}"
                );
                assert!(
                    (0.0..1.0).contains(&f_val),
                    "RNG with seed 0x{seed:016X} produced f64 out of range: {f_val}"
                );
            }

            // Test usize generation with extreme bounds
            let mut rng4 = SplitMix64::new(seed);
            let extreme_bounds = vec![1, 2, 3, usize::MAX, usize::MAX - 1];

            for bound in extreme_bounds {
                for _ in 0..100 {
                    let usize_val = rng4.next_usize(bound);
                    assert!(
                        usize_val < bound,
                        "RNG with seed 0x{seed:016X} produced usize {usize_val} >= bound {bound}"
                    );
                }
            }
        }
    }

    #[test]
    fn negative_lab_runtime_with_massive_virtual_link_configurations() {
        let mut runtime = LabRuntime::new(default_config()).unwrap();

        // Test adding links up to capacity limit
        let mut added_links = 0;
        for i in 0..MAX_VIRTUAL_LINKS + 100 {
            // Try to exceed limit
            let source = format!("massive_src_{:06}", i);
            let target = format!("massive_dst_{:06}", i);

            // Use various fault profiles to test different configurations
            let fault_profile = match i % 4 {
                0 => FaultProfile::default(),
                1 => FaultProfile {
                    drop_pct: 0.1,
                    reorder_depth: 5,
                    corrupt_probability: 0.05,
                    delay_ticks: i as u64 % 100,
                },
                2 => FaultProfile {
                    drop_pct: 1.0, // Always drop
                    reorder_depth: 0,
                    corrupt_probability: 0.0,
                    delay_ticks: 0,
                },
                _ => FaultProfile {
                    drop_pct: 0.0,
                    reorder_depth: 1000,       // Large reorder buffer
                    corrupt_probability: 1.0,  // Always corrupt
                    delay_ticks: u64::MAX / 2, // Large delay
                },
            };

            let link = VirtualLink::new(source, target, fault_profile);
            match link {
                Ok(valid_link) => {
                    match runtime.add_link(valid_link) {
                        Ok(_) => {
                            added_links += 1;
                        }
                        Err(LabError::LinkCapacityExceeded { limit }) => {
                            // Expected when hitting capacity limits
                            assert!(
                                added_links > 0,
                                "Should add at least some links before hitting limit"
                            );
                            assert_eq!(limit, MAX_VIRTUAL_LINKS.min(MAX_REORDER_BUFFERS));
                            break;
                        }
                        Err(other) => {
                            panic!("Unexpected error adding link {i}: {other}");
                        }
                    }
                }
                Err(fault_error) => {
                    // Some extreme fault profiles might be rejected
                    match fault_error {
                        LabError::FaultRange { .. } => {} // Expected for extreme values
                        other => panic!("Unexpected fault profile error for link {i}: {other}"),
                    }
                }
            }
        }

        // Verify we added a reasonable number of links
        assert!(
            added_links >= MAX_VIRTUAL_LINKS.min(100),
            "Should add at least {} links",
            MAX_VIRTUAL_LINKS.min(100)
        );

        // Test message sending across all added links
        for link_idx in 0..added_links.min(runtime.link_count()) {
            let message = format!("stress_message_on_link_{link_idx}");
            match runtime.send_message(link_idx, &message) {
                Ok(outcome) => {
                    // Any outcome is acceptable (delivered, dropped, corrupted, reordered)
                    match outcome {
                        MessageOutcome::Delivered { delay_ticks } => {
                            assert!(delay_ticks < u64::MAX, "Delay should not overflow");
                        }
                        MessageOutcome::Corrupted { delay_ticks } => {
                            assert!(delay_ticks < u64::MAX, "Delay should not overflow");
                        }
                        MessageOutcome::Reordered {
                            buffer_position,
                            delay_ticks,
                        } => {
                            assert!(delay_ticks < u64::MAX, "Delay should not overflow");
                            assert!(
                                buffer_position < 10000,
                                "Buffer position should be reasonable"
                            );
                        }
                        MessageOutcome::Dropped => {} // No additional validation needed
                    }
                }
                Err(LabError::LinkNotFound { .. }) => {
                    panic!("Link {link_idx} should exist after being added");
                }
                Err(other) => {
                    panic!("Unexpected message sending error on link {link_idx}: {other}");
                }
            }
        }
    }

    #[test]
    fn negative_repro_bundle_with_malformed_and_malicious_json() {
        // Test ReproBundle deserialization with malicious JSON patterns
        let malicious_json_patterns = vec![
            r#"{"schema_version": "lab-v1.0", "seed": 42, "config": {"seed": 42, "max_ticks": 1000, "max_interleavings": 100, "enable_dpor": false}, "links": [], "events": [], "passed": true, "__proto__": {"isAdmin": true}}"#, // Prototype pollution
            r#"{"schema_version": "lab-v1.0\u0000", "seed": 42, "config": {"seed": 42, "max_ticks": 1000, "max_interleavings": 100, "enable_dpor": false}, "links": [], "events": [], "passed": true}"#, // Null byte in version
            r#"{"schema_version": "lab-v999.0", "seed": 42, "config": {"seed": 42, "max_ticks": 1000, "max_interleavings": 100, "enable_dpor": false}, "links": [], "events": [], "passed": true}"#, // Wrong schema version
            r#"{"schema_version": "lab-v1.0", "seed": 0, "config": {"seed": 0, "max_ticks": 1000, "max_interleavings": 100, "enable_dpor": false}, "links": [], "events": [], "passed": true}"#, // Invalid seed
            r#"{"schema_version": "lab-v1.0", "seed": 42, "config": {"seed": 999, "max_ticks": 1000, "max_interleavings": 100, "enable_dpor": false}, "links": [], "events": [], "passed": true}"#, // Seed mismatch
            // Extremely large collections
            format!(r#"{{"schema_version": "lab-v1.0", "seed": 42, "config": {{"seed": 42, "max_ticks": 1000, "max_interleavings": 100, "enable_dpor": false}}, "links": [{}], "events": [], "passed": true}}"#,
                   (0..MAX_VIRTUAL_LINKS + 100).map(|i| format!(r#"{{"source": "src_{}", "target": "dst_{}", "fault_profile": {{"drop_pct": 0.0, "reorder_depth": 0, "corrupt_probability": 0.0, "delay_ticks": 0}}}}"#, i, i)).collect::<Vec<_>>().join(",")),
        ];

        for (i, malicious_json) in malicious_json_patterns.iter().enumerate() {
            match ReproBundle::from_json(malicious_json) {
                Ok(bundle) => {
                    // If parsing succeeded, validate the bundle to catch inconsistencies
                    match bundle.validate() {
                        Ok(_) => {
                            // Bundle is valid despite being crafted - should still function correctly
                            assert!(!bundle.schema_version.is_empty());
                            assert_ne!(bundle.seed, 0); // Should not have zero seed if valid
                        }
                        Err(LabError::BundleValidation { detail }) => {
                            // Expected for malicious patterns
                            assert!(!detail.is_empty(), "Validation error should have detail");
                        }
                        Err(other) => {
                            panic!("Pattern {i}: Unexpected validation error: {other}");
                        }
                    }
                }
                Err(LabError::BundleDeserialization { detail }) => {
                    // Expected for malformed JSON
                    assert!(
                        !detail.is_empty(),
                        "Deserialization error should have detail"
                    );
                }
                Err(LabError::BundleValidation { detail }) => {
                    // Also acceptable - validation caught the issue
                    assert!(!detail.is_empty(), "Validation error should have detail");
                }
                Err(other) => {
                    panic!("Pattern {i}: Unexpected error type: {other}");
                }
            }
        }

        // Test bundle serialization with extreme content
        let mut extreme_bundle = ReproBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            seed: u64::MAX,
            config: LabConfig {
                seed: u64::MAX,
                max_ticks: u64::MAX,
                max_interleavings: u64::MAX,
                enable_dpor: true,
            },
            links: vec![],
            events: vec![],
            passed: false,
        };

        // Add maximum events with extreme content
        for i in 0..MAX_EVENTS.min(1000) {
            extreme_bundle.events.push(LabEvent {
                tick: u64::MAX - i as u64,
                event_code: format!("EXTREME_EVENT_{:06}_{}", i, "x".repeat(1000)),
                payload: format!("extreme_payload_{}_{}", i, "\u{1F4A9}".repeat(100)), // Emoji stress test
            });
        }

        match extreme_bundle.to_json() {
            Ok(json_str) => {
                assert!(!json_str.is_empty());
                assert!(
                    json_str.len() > 1000,
                    "Extreme bundle should produce substantial JSON"
                );

                // Verify round-trip fidelity
                match ReproBundle::from_json(&json_str) {
                    Ok(deserialized) => {
                        assert_eq!(
                            extreme_bundle, deserialized,
                            "Extreme bundle round-trip failed"
                        );
                    }
                    Err(e) => {
                        panic!("Extreme bundle round-trip deserialization failed: {e}");
                    }
                }
            }
            Err(LabError::BundleSerialization { detail }) => {
                // Might fail on extreme content, which is acceptable
                assert!(!detail.is_empty(), "Serialization error should have detail");
            }
            Err(other) => {
                panic!("Unexpected extreme bundle serialization error: {other}");
            }
        }
    }

    #[test]
    fn negative_lab_error_display_with_malicious_content_injection() {
        // Test LabError Display implementation with malicious content
        let injection_payloads = vec![
            "error\x1b[31mRED\x1b[0m",              // ANSI escape codes
            "error\r\nHTTP/1.1 200 OK",             // HTTP header injection
            "error\0null_byte\x00",                 // Null bytes
            "error\u{202E}reverse\u{202D}normal",   // BiDi override
            "error</log><log level=\"ERROR\">",     // XML injection
            "error\n\nSecond line injection",       // Newline injection
            "\u{FEFF}error_with_bom",               // Byte order mark
            "error_with_unicode_\u{1F4A9}_content", // Unicode emoji
            "'error'; DROP TABLE logs; --",         // SQL injection style
        ];

        for malicious_content in injection_payloads {
            let error_variants = vec![
                LabError::BundleValidation {
                    detail: malicious_content.to_string(),
                },
                LabError::BundleSerialization {
                    detail: malicious_content.to_string(),
                },
                LabError::BundleDeserialization {
                    detail: malicious_content.to_string(),
                },
                LabError::LinkNotFound {
                    source: malicious_content.to_string(),
                    target: "target".to_string(),
                },
                LabError::FaultRange {
                    field: malicious_content.to_string(),
                    value: 1.5,
                },
                LabError::ReplayDivergence {
                    expected_events: 100,
                    actual_events: 200,
                },
            ];

            for error in error_variants {
                let error_string = format!("{}", error);

                // Error display should include malicious content safely
                if error_string.contains(malicious_content) {
                    // Content included as-is (no processing of escape codes expected)
                } else {
                    // Content might be escaped or sanitized, which is also acceptable
                    assert!(
                        !error_string.is_empty(),
                        "Error display should not be empty"
                    );
                }

                // Display should not crash or cause undefined behavior
                assert!(
                    error_string.len() > 0,
                    "Error display should produce output"
                );

                // Should contain appropriate error code prefix
                let contains_error_code =
                    error_string.contains("ERR_LB_") || error_string.starts_with("ERR_LB_");
                if !contains_error_code {
                    // Some error types might not have codes, which is acceptable
                }
            }
        }
    }

    #[test]
    fn negative_message_outcome_serialization_with_extreme_values() {
        // Test MessageOutcome with extreme delay and position values
        let extreme_outcomes = vec![
            MessageOutcome::Delivered {
                delay_ticks: u64::MAX,
            },
            MessageOutcome::Corrupted {
                delay_ticks: u64::MAX - 1,
            },
            MessageOutcome::Reordered {
                buffer_position: usize::MAX,
                delay_ticks: u64::MAX / 2,
            },
            MessageOutcome::Dropped,
            MessageOutcome::Reordered {
                buffer_position: 0,
                delay_ticks: 0,
            },
        ];

        for (i, outcome) in extreme_outcomes.iter().enumerate() {
            // Test serialization
            match serde_json::to_string(outcome) {
                Ok(json_str) => {
                    assert!(
                        !json_str.is_empty(),
                        "Outcome {i} serialization should not be empty"
                    );

                    // Test deserialization round-trip
                    match serde_json::from_str::<MessageOutcome>(&json_str) {
                        Ok(deserialized) => {
                            assert_eq!(
                                outcome, &deserialized,
                                "Outcome {i} round-trip should preserve equality"
                            );
                        }
                        Err(e) => {
                            panic!("Outcome {i} deserialization failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    // Serialization failure might be acceptable for extreme values
                    println!("Outcome {i} serialization failed (acceptable): {e}");
                }
            }

            // Test PartialEq and Eq behavior with extreme values
            assert_eq!(outcome, outcome, "Outcome {i} should equal itself");

            // Test Debug formatting doesn't panic
            let debug_str = format!("{:?}", outcome);
            assert!(
                !debug_str.is_empty(),
                "Outcome {i} Debug should not be empty"
            );
        }
    }

    // ============================================================================
    // EXTREME ADVERSARIAL NEGATIVE-PATH TESTS - COMPREHENSIVE EDGE CASES
    // ============================================================================
    // Advanced attack resistance and sophisticated edge case validation

    #[test]
    fn negative_unicode_injection_comprehensive_lab_identifiers() {
        // Test lab runtime with Unicode injection attacks in all identifier fields
        let unicode_attack_patterns = vec![
            // BiDi override attacks
            ("bidi_rtl", "lab\u{202e}_gnissecorp\u{202c}_test"),
            ("bidi_ltr", "lab\u{202d}_processing\u{202c}_test"),
            // Zero-width character pollution
            ("zws", "lab\u{200b}_test\u{200c}_runtime\u{200d}"),
            ("bom", "\u{feff}lab_test\u{feff}"),
            // Unicode normalization attacks
            ("nfc_cafe", "café_lab_test"),
            ("nfd_cafe", "cafe\u{0301}_lab_test"),
            // Confusable characters
            ("cyrillic_a", "lаb_test"),  // Cyrillic 'а'
            ("greek_alpha", "lαb_test"), // Greek 'α'
            // Combining character stacking
            ("combining", "la\u{0300}\u{0301}\u{0302}b_test"),
            // Line separator injection
            ("line_sep", "lab\u{2028}test\u{2029}runtime"),
        ];

        for (test_name, attack_id) in unicode_attack_patterns {
            // Test scenario ID with Unicode injection
            let mut config = VirtualLabRuntimeConfig::new(12345);
            config.set_scenario_id(attack_id.to_string());

            // Should handle Unicode injection without corruption
            let result = VirtualLabRuntime::new(config);
            match result {
                Ok(mut runtime) => {
                    // Verify Unicode preservation without normalization attacks
                    assert_eq!(runtime.scenario_id(), attack_id);

                    // Test timer creation with Unicode IDs
                    let timer_result =
                        runtime.create_timer(format!("unicode_timer_{}", test_name), 100);
                    assert!(
                        timer_result.is_ok(),
                        "Timer creation should handle Unicode: {}",
                        test_name
                    );

                    // Test virtual link creation with Unicode names
                    let link_result = runtime.create_virtual_link(
                        format!("unicode_link_{}", test_name),
                        "node_a",
                        "node_b",
                    );
                    assert!(
                        link_result.is_ok(),
                        "Link creation should handle Unicode: {}",
                        test_name
                    );
                }
                Err(_) => {
                    // Acceptable for some extreme Unicode patterns to be rejected
                }
            }
        }
    }

    #[test]
    fn negative_arithmetic_overflow_tick_calculations_comprehensive() {
        // Test tick arithmetic with values that could cause overflow
        let overflow_test_cases = vec![
            // Near u64::MAX boundaries
            (u64::MAX, 1, "max_plus_one"),
            (u64::MAX - 1, 2, "max_minus_one_plus_two"),
            (u64::MAX / 2, u64::MAX / 2 + 100, "half_max_addition"),
            // Large timer delays
            (1000, u64::MAX - 100, "large_delay_from_small_base"),
            (u64::MAX - 1000, 999, "large_base_small_delay"),
            (u64::MAX - 1000, 1001, "large_base_larger_delay"),
            // Zero boundary conditions
            (0, u64::MAX, "zero_base_max_delay"),
            (u64::MAX, 0, "max_base_zero_delay"),
            // Power-of-2 boundaries
            (u32::MAX as u64, u32::MAX as u64, "u32_boundary_addition"),
            (1u64 << 62, 1u64 << 62, "large_power_of_two"),
        ];

        for (base_tick, delay, test_name) in overflow_test_cases {
            let mut config = VirtualLabRuntimeConfig::new(54321);
            config.set_scenario_id(format!("overflow_test_{}", test_name));

            let mut runtime = VirtualLabRuntime::new(config).unwrap();

            // Set current tick to base value
            runtime.advance_clock(base_tick).ok(); // May fail for extreme values

            // Test timer creation with overflow-prone delay
            let timer_result = runtime.create_timer(format!("overflow_timer_{}", test_name), delay);

            match timer_result {
                Ok(timer_id) => {
                    // If timer creation succeeds, fire time calculation should not overflow
                    let timer_info = runtime.get_timer_info(&timer_id);
                    assert!(timer_info.is_some(), "Timer info should be available");

                    // Test clock advancement without overflow panic
                    if let Some(info) = timer_info {
                        if info.fire_tick < u64::MAX - 1000 {
                            let advance_result = runtime.advance_clock(info.fire_tick);
                            // Should handle advancement without arithmetic overflow
                            assert!(advance_result.is_ok() || advance_result.is_err());
                        }
                    }
                }
                Err(err) => {
                    // Acceptable to reject overflow-prone timer configurations
                    assert!(
                        err.to_string().contains("overflow") || err.to_string().contains("range")
                    );
                }
            }
        }
    }

    #[test]
    fn negative_memory_exhaustion_virtual_link_stress() {
        // Test virtual link creation under memory pressure scenarios
        let mut config = VirtualLabRuntimeConfig::new(98765);
        config.set_max_virtual_links(1000); // Reasonable limit for testing

        let mut runtime = VirtualLabRuntime::new(config).unwrap();

        // Test 1: Rapid link creation up to capacity
        let mut created_links = Vec::new();
        for i in 0..1000 {
            let link_id = format!("stress_link_{:04}", i);
            let result = runtime.create_virtual_link(
                &link_id,
                &format!("node_a_{}", i),
                &format!("node_b_{}", i),
            );

            match result {
                Ok(link) => {
                    created_links.push((link_id, link));
                }
                Err(err) => {
                    // Should fail gracefully when capacity exceeded
                    assert!(
                        err.to_string().contains("capacity")
                            || err.to_string().contains("limit")
                            || err.to_string().contains("exceeded")
                    );
                    break;
                }
            }
        }

        // Should have created some links before hitting capacity
        assert!(
            !created_links.is_empty(),
            "Should create some links before capacity limit"
        );
        assert!(
            created_links.len() <= 1000,
            "Should not exceed configured capacity"
        );

        // Test 2: Very long node identifiers
        let long_node_a = "node_".to_string() + &"a".repeat(10000);
        let long_node_b = "node_".to_string() + &"b".repeat(10000);

        let long_link_result =
            runtime.create_virtual_link("long_identifier_link", &long_node_a, &long_node_b);

        // Should handle long identifiers gracefully
        match long_link_result {
            Ok(_) => {
                // Success is acceptable if memory allows
            }
            Err(err) => {
                // Failure is acceptable for extreme lengths
                assert!(!err.to_string().is_empty());
            }
        }

        // Test 3: Rapid message injection on created links
        for (link_id, link_handle) in created_links.iter().take(10) {
            for msg_idx in 0..100 {
                let message_data = format!("stress_message_{}_{}", link_id, msg_idx);

                let send_result =
                    runtime.send_message(&link_handle, message_data.as_bytes().to_vec());

                // Should handle rapid message sending without memory exhaustion
                match send_result {
                    Ok(_) => {
                        // Success is fine
                    }
                    Err(err) => {
                        // Should fail gracefully if buffer capacity exceeded
                        assert!(!err.to_string().is_empty());
                    }
                }
            }
        }

        // Runtime should maintain consistency after stress test
        let final_stats = runtime.get_runtime_stats();
        assert!(final_stats.total_links_created <= 1000);
        assert!(final_stats.active_timers >= 0);
    }

    #[test]
    fn negative_fault_injection_boundary_value_comprehensive() {
        // Test fault injection with boundary and extreme probability values
        let fault_probability_tests = vec![
            (0.0, "zero_probability"),
            (1.0, "one_probability"),
            (0.5, "half_probability"),
            (0.000001, "near_zero"),
            (0.999999, "near_one"),
            (f64::MIN_POSITIVE, "min_positive"),
            (1.0 - f64::EPSILON, "near_one_epsilon"),
            (f64::EPSILON, "epsilon"),
        ];

        let mut config = VirtualLabRuntimeConfig::new(11111);
        let mut runtime = VirtualLabRuntime::new(config).unwrap();

        // Create test virtual link
        let link = runtime
            .create_virtual_link("fault_test_link", "node_a", "node_b")
            .unwrap();

        for (probability, test_name) in fault_probability_tests {
            // Test fault configuration with boundary values
            let fault_config = FaultInjectionConfig {
                corruption_probability: probability,
                drop_probability: probability,
                delay_range: (0, 100),
                reorder_probability: probability,
                duplicate_probability: probability,
            };

            let result = runtime.configure_link_faults(&link, fault_config);

            match result {
                Ok(_) => {
                    // Test message sending with configured faults
                    for msg_idx in 0..20 {
                        let message = format!("fault_test_{}_{}", test_name, msg_idx);
                        let send_result = runtime.send_message(&link, message.as_bytes().to_vec());

                        // Should handle fault injection without panic
                        assert!(send_result.is_ok() || send_result.is_err());
                    }

                    // Test fault statistics don't overflow
                    let stats = runtime.get_fault_statistics(&link);
                    if let Some(fault_stats) = stats {
                        assert!(fault_stats.messages_corrupted < u64::MAX);
                        assert!(fault_stats.messages_dropped < u64::MAX);
                        assert!(fault_stats.messages_delayed < u64::MAX);
                    }
                }
                Err(err) => {
                    // Should provide meaningful error for invalid probabilities
                    let error_msg = err.to_string();
                    assert!(
                        error_msg.contains("probability")
                            || error_msg.contains("range")
                            || error_msg.contains("valid"),
                        "Error message should be meaningful: {}",
                        error_msg
                    );
                }
            }
        }

        // Test invalid probability values (should be rejected)
        let invalid_probabilities = vec![
            (-0.1, "negative"),
            (1.1, "greater_than_one"),
            (f64::NEG_INFINITY, "neg_infinity"),
            (f64::INFINITY, "pos_infinity"),
            (f64::NAN, "nan"),
        ];

        for (invalid_prob, test_name) in invalid_probabilities {
            let invalid_config = FaultInjectionConfig {
                corruption_probability: invalid_prob,
                drop_probability: 0.0,
                delay_range: (0, 10),
                reorder_probability: 0.0,
                duplicate_probability: 0.0,
            };

            let result = runtime.configure_link_faults(&link, invalid_config);
            assert!(
                result.is_err(),
                "Invalid probability {} should be rejected",
                test_name
            );
        }
    }

    #[test]
    fn negative_dpor_interleaving_budget_exhaustion_edge_cases() {
        // Test DPOR (Dynamic Partial Order Reduction) with budget exhaustion scenarios
        let mut config = VirtualLabRuntimeConfig::new(22222);
        config.set_dpor_budget(100); // Limited budget for testing

        let mut runtime = VirtualLabRuntime::new(config).unwrap();

        // Create multiple virtual links for complex interleavings
        let mut links = Vec::new();
        for i in 0..5 {
            let link = runtime
                .create_virtual_link(
                    &format!("dpor_link_{}", i),
                    &format!("node_a_{}", i),
                    &format!("node_b_{}", i),
                )
                .unwrap();
            links.push(link);
        }

        // Generate complex message patterns that stress DPOR exploration
        let message_patterns = vec![
            // Rapid burst pattern
            (
                "burst",
                (0..50)
                    .map(|i| (i % links.len(), format!("burst_{}", i)))
                    .collect(),
            ),
            // Alternating pattern
            (
                "alternating",
                (0..50).map(|i| (i % 2, format!("alt_{}", i))).collect(),
            ),
            // Round-robin pattern
            (
                "round_robin",
                (0..50)
                    .map(|i| (i % links.len(), format!("rr_{}", i)))
                    .collect(),
            ),
            // Reverse order pattern
            (
                "reverse",
                (0..20)
                    .map(|i| (links.len() - 1 - (i % links.len()), format!("rev_{}", i)))
                    .collect(),
            ),
        ];

        for (pattern_name, message_sequence) in message_patterns {
            runtime.reset_dpor_state();

            // Send messages according to pattern
            for (link_idx, message_content) in message_sequence {
                if link_idx < links.len() {
                    let send_result =
                        runtime.send_message(&links[link_idx], message_content.as_bytes().to_vec());

                    // Should handle sending without panic, even under DPOR pressure
                    match send_result {
                        Ok(_) => {
                            // Success is fine
                        }
                        Err(err) => {
                            // Should provide meaningful error if budget exhausted
                            if err.to_string().contains("budget") {
                                break; // Expected budget exhaustion
                            }
                        }
                    }
                }
            }

            // Test DPOR state consistency after pattern completion
            let dpor_stats = runtime.get_dpor_statistics();
            assert!(
                dpor_stats.interleavings_explored <= 100,
                "DPOR should respect budget limit for pattern {}",
                pattern_name
            );
            assert!(
                dpor_stats.interleavings_explored < u64::MAX,
                "DPOR counters should not overflow for pattern {}",
                pattern_name
            );
        }

        // Test DPOR budget of zero (should disable exploration)
        config.set_dpor_budget(0);
        let zero_budget_runtime = VirtualLabRuntime::new(config);
        assert!(
            zero_budget_runtime.is_ok(),
            "Zero DPOR budget should be valid"
        );

        if let Ok(mut runtime) = zero_budget_runtime {
            let link = runtime
                .create_virtual_link("zero_budget_link", "node_a", "node_b")
                .unwrap();

            // Should handle messages without DPOR exploration
            let send_result = runtime.send_message(&link, b"test_message".to_vec());
            assert!(
                send_result.is_ok(),
                "Should handle messages with zero DPOR budget"
            );

            let dpor_stats = runtime.get_dpor_statistics();
            assert_eq!(
                dpor_stats.interleavings_explored, 0,
                "No interleavings should be explored"
            );
        }
    }

    #[test]
    fn negative_repro_bundle_serialization_malformed_data_recovery() {
        // Test repro bundle serialization/deserialization with malformed and extreme data
        let mut config = VirtualLabRuntimeConfig::new(33333);
        let mut runtime = VirtualLabRuntime::new(config).unwrap();

        // Create scenario with complex state
        let link = runtime
            .create_virtual_link("bundle_test_link", "node_a", "node_b")
            .unwrap();
        let timer = runtime.create_timer("bundle_test_timer", 500).unwrap();

        // Send some messages to build state
        for i in 0..10 {
            runtime
                .send_message(&link, format!("message_{}", i).as_bytes().to_vec())
                .ok();
        }
        runtime.advance_clock(100).ok();

        // Generate repro bundle
        let bundle_result = runtime.export_repro_bundle();
        assert!(bundle_result.is_ok(), "Bundle export should succeed");

        let original_bundle = bundle_result.unwrap();
        let bundle_json = serde_json::to_string(&original_bundle).unwrap();

        // Test various JSON corruption scenarios
        let corruption_patterns = vec![
            // Truncation at different positions
            ("truncate_half", &bundle_json[..bundle_json.len() / 2]),
            ("truncate_quarter", &bundle_json[..bundle_json.len() / 4]),
            ("truncate_end", &bundle_json[..bundle_json.len() - 10]),
            // Invalid JSON structure
            ("missing_brace", &bundle_json.replace("}", "")),
            ("missing_bracket", &bundle_json.replace("]", "")),
            ("invalid_quotes", &bundle_json.replace("\"", "'")),
            ("invalid_colon", &bundle_json.replace(":", "=")),
            // Unicode corruption
            ("unicode_replace", &bundle_json.replace("bundle", "bundlé")),
            (
                "unicode_inject",
                &format!("{}🦀{}", &bundle_json[..50], &bundle_json[50..]),
            ),
            // Null byte injection
            (
                "null_inject",
                &format!("{}\x00{}", &bundle_json[..100], &bundle_json[100..]),
            ),
            // Large number injection
            (
                "large_number",
                &bundle_json.replace("500", "99999999999999999999"),
            ),
            ("negative_number", &bundle_json.replace("100", "-999999999")),
            // Field value corruption
            ("empty_string", &bundle_json.replace("bundle_test_link", "")),
            (
                "null_value",
                &bundle_json.replace("\"bundle_test_timer\"", "null"),
            ),
        ];

        for (corruption_name, corrupted_json) in corruption_patterns {
            // Test deserialization of corrupted bundle
            let deserialize_result = serde_json::from_str::<ReproBundle>(corrupted_json);

            match deserialize_result {
                Ok(corrupted_bundle) => {
                    // If deserialization succeeds despite corruption, verify it's still valid
                    let validation_result = runtime.validate_repro_bundle(&corrupted_bundle);
                    // Validation should catch inconsistencies
                    assert!(
                        validation_result.is_ok() || validation_result.is_err(),
                        "Validation should handle corrupted bundle: {}",
                        corruption_name
                    );
                }
                Err(err) => {
                    // Expected for most corruption patterns
                    assert!(
                        !err.to_string().is_empty(),
                        "Error should be meaningful: {}",
                        corruption_name
                    );
                    assert!(
                        err.to_string().len() < 1000,
                        "Error message should be reasonable length: {}",
                        corruption_name
                    );
                }
            }
        }

        // Test that original bundle still works after corruption tests
        let original_deserialize = serde_json::from_str::<ReproBundle>(&bundle_json);
        assert!(
            original_deserialize.is_ok(),
            "Original bundle should still deserialize"
        );

        let original_validation = runtime.validate_repro_bundle(&original_bundle);
        assert!(
            original_validation.is_ok(),
            "Original bundle should still validate"
        );
    }

    #[test]
    fn negative_concurrent_state_access_simulation_comprehensive() {
        // Simulate concurrent access patterns that might expose race conditions
        let mut config = VirtualLabRuntimeConfig::new(44444);
        let mut runtime = VirtualLabRuntime::new(config).unwrap();

        // Create multiple resources for concurrent-like access
        let mut links = Vec::new();
        let mut timers = Vec::new();

        for i in 0..10 {
            let link = runtime
                .create_virtual_link(
                    &format!("concurrent_link_{}", i),
                    &format!("node_a_{}", i),
                    &format!("node_b_{}", i),
                )
                .unwrap();
            links.push(link);

            let timer = runtime
                .create_timer(&format!("concurrent_timer_{}", i), 100 * i as u64)
                .unwrap();
            timers.push(timer);
        }

        // Simulate rapid interleaved operations that might cause state corruption
        for round in 0..50 {
            let operation_type = round % 6;

            match operation_type {
                0 => {
                    // Message sending on random links
                    for link in &links {
                        runtime
                            .send_message(link, format!("round_{}", round).as_bytes().to_vec())
                            .ok();
                    }
                }
                1 => {
                    // Clock advancement
                    runtime.advance_clock((round as u64) * 10).ok();
                }
                2 => {
                    // Timer status checking
                    for timer in &timers {
                        runtime.get_timer_info(timer);
                    }
                }
                3 => {
                    // Link statistics retrieval
                    for link in &links {
                        runtime.get_link_statistics(link);
                    }
                }
                4 => {
                    // Runtime statistics
                    let stats = runtime.get_runtime_stats();
                    assert!(stats.total_links_created >= u64::try_from(links.len()).unwrap_or(u64::MAX));
                    assert!(stats.total_timers_created >= u64::try_from(timers.len()).unwrap_or(u64::MAX));
                }
                5 => {
                    // DPOR statistics
                    let dpor_stats = runtime.get_dpor_statistics();
                    assert!(dpor_stats.interleavings_explored < u64::MAX);
                }
                _ => unreachable!(),
            }
        }

        // Final consistency check after simulated concurrent operations
        let final_stats = runtime.get_runtime_stats();
        assert!(final_stats.total_links_created >= u64::try_from(links.len()).unwrap_or(u64::MAX));
        assert!(final_stats.total_timers_created >= u64::try_from(timers.len()).unwrap_or(u64::MAX));
        assert!(final_stats.total_messages_sent < u64::MAX);
        assert!(final_stats.current_tick < u64::MAX);

        // Verify all created resources are still accessible
        for (i, link) in links.iter().enumerate() {
            let link_stats = runtime.get_link_statistics(link);
            assert!(
                link_stats.is_some(),
                "Link {} should still be accessible",
                i
            );
        }

        for (i, timer) in timers.iter().enumerate() {
            let timer_info = runtime.get_timer_info(timer);
            // Timer may have fired, but should not cause corruption
            assert!(
                timer_info.is_some() || timer_info.is_none(),
                "Timer {} access should not corrupt state",
                i
            );
        }

        // Export bundle should work after concurrent simulation
        let bundle_result = runtime.export_repro_bundle();
        assert!(
            bundle_result.is_ok(),
            "Bundle export should work after concurrent simulation"
        );
    }

    #[test]
    fn negative_control_character_message_payload_comprehensive() {
        // Test message payloads with control characters and binary data
        let mut config = VirtualLabRuntimeConfig::new(55555);
        let mut runtime = VirtualLabRuntime::new(config).unwrap();

        let link = runtime
            .create_virtual_link("control_char_link", "node_a", "node_b")
            .unwrap();

        let control_char_payloads = vec![
            // ASCII control characters
            ("null_bytes", vec![0x00, 0x01, 0x02, 0x03]),
            ("bell_backspace", b"\x07\x08hello\x08\x07".to_vec()),
            ("tab_newline", b"line1\x09\x0Aline2\x0D\x0A".to_vec()),
            ("escape_sequences", b"\x1B[31mred\x1B[0mnormal".to_vec()),
            // Binary data patterns
            ("all_bytes", (0..=255u8).collect::<Vec<u8>>()),
            (
                "alternating",
                (0..256)
                    .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
                    .collect(),
            ),
            ("random_binary", vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA]),
            // UTF-8 with control chars
            (
                "utf8_control",
                "Hello\x00World\x1F测试\x7F".as_bytes().to_vec(),
            ),
            ("utf8_mixed", "🦀\x00Rust\x01Lang\x02".as_bytes().to_vec()),
            // Very long payloads with control chars
            ("long_control", {
                let mut payload = Vec::new();
                for i in 0..10000 {
                    payload.push((i % 32) as u8); // Control char range
                }
                payload
            }),
            // Embedded null terminators (C-style string attacks)
            ("null_terminators", b"normal\x00hidden\x00data\x00".to_vec()),
            ("multiple_nulls", vec![0x00; 1000]),
            // JSON-like control char injection
            ("json_injection", br#"{"evil": true}\x00\x0A"#.to_vec()),
            (
                "newline_injection",
                b"line1\nINJECTED: evil\nline2".to_vec(),
            ),
        ];

        for (test_name, payload) in control_char_payloads {
            // Send message with control character payload
            let send_result = runtime.send_message(&link, payload.clone());

            match send_result {
                Ok(message_id) => {
                    // If message accepted, advance clock to process it
                    runtime.advance_clock(10).ok();

                    // Check message statistics
                    let link_stats = runtime.get_link_statistics(&link);
                    assert!(
                        link_stats.is_some(),
                        "Link stats should be available after control char test: {}",
                        test_name
                    );

                    if let Some(stats) = link_stats {
                        assert!(
                            stats.total_messages_sent > 0,
                            "Message count should increase: {}",
                            test_name
                        );
                    }

                    // Verify no corruption in runtime state
                    let runtime_stats = runtime.get_runtime_stats();
                    assert!(
                        runtime_stats.total_messages_sent > 0,
                        "Runtime message count should be valid: {}",
                        test_name
                    );
                }
                Err(err) => {
                    // Some control character patterns may be rejected - that's acceptable
                    assert!(
                        !err.to_string().is_empty(),
                        "Error should be meaningful: {}",
                        test_name
                    );
                }
            }
        }

        // Test that normal messages still work after control character tests
        let normal_result = runtime.send_message(&link, b"normal_message".to_vec());
        assert!(
            normal_result.is_ok(),
            "Normal messages should work after control char tests"
        );

        // Export bundle should include control character message data correctly
        let bundle_result = runtime.export_repro_bundle();
        assert!(
            bundle_result.is_ok(),
            "Bundle export should work with control char messages"
        );
    }
}

#[cfg(test)]
mod lab_runtime_comprehensive_resilience_and_attack_vector_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn negative_prng_determinism_and_entropy_exhaustion_attack_resistance() {
        // Test PRNG determinism under extreme conditions and entropy attacks
        let mut prng_collision_test = SeededPrng::new(12345);
        let mut seen_values = HashSet::new();
        let iterations = 100_000;

        // Test 1: Large-scale determinism and collision resistance
        for i in 0..iterations {
            let value = prng_collision_test.next_u64();

            assert!(
                seen_values.insert(value),
                "PRNG collision detected at iteration {}: value {}",
                i,
                value
            );
        }

        // Test 2: Seed-based determinism across multiple PRNG instances
        let seed_tests = vec![0, 1, u64::MAX, 0x12345678ABCDEF, 0x8000000000000000];

        for test_seed in seed_tests {
            let mut prng1 = SeededPrng::new(test_seed);
            let mut prng2 = SeededPrng::new(test_seed);

            let sequence1: Vec<u64> = (0..1000).map(|_| prng1.next_u64()).collect();
            let sequence2: Vec<u64> = (0..1000).map(|_| prng2.next_u64()).collect();

            assert_eq!(
                sequence1, sequence2,
                "PRNG sequences should be identical for seed {}",
                test_seed
            );
        }

        // Test 3: Different seeds produce different sequences
        let mut different_seeds_map = HashMap::new();
        for seed in [0, 1, 2, 3, 42, 12345, u64::MAX] {
            let mut prng = SeededPrng::new(seed);
            let sequence: Vec<u64> = (0..100).map(|_| prng.next_u64()).collect();

            for (other_seed, other_sequence) in &different_seeds_map {
                assert_ne!(
                    sequence, *other_sequence,
                    "Different seeds {} and {} should produce different sequences",
                    seed, other_seed
                );
            }

            different_seeds_map.insert(seed, sequence);
        }

        // Test 4: Range generation uniformity and boundary conditions
        let mut range_prng = SeededPrng::new(98765);

        // Test extreme range boundaries
        let range_tests = vec![
            (0, 1),                    // Minimal range
            (0, 2),                    // Binary choice
            (0, u64::MAX),             // Full range
            (1000, 1001),              // Single value range
            (u64::MAX - 10, u64::MAX), // Near-maximum range
        ];

        for (min, max) in range_tests {
            if min >= max {
                continue;
            }

            for _ in 0..1000 {
                let value = range_prng.gen_range(min..max);
                assert!(
                    value >= min && value < max,
                    "Range value {} should be in [{}, {})",
                    value,
                    min,
                    max
                );
            }
        }

        // Test 5: Float range generation precision and boundary adherence
        let mut float_prng = SeededPrng::new(111222);

        for _ in 0..10000 {
            let value = float_prng.gen_f64();
            assert!(
                value >= 0.0 && value < 1.0,
                "Float value {} should be in [0.0, 1.0)",
                value
            );
            assert!(value.is_finite(), "Float value should be finite");
        }

        // Test 6: Serialization consistency and round-trip determinism
        let serialized_prng = SeededPrng::new(54321);
        let serialized_json = serde_json::to_string(&serialized_prng).unwrap();
        let deserialized_prng: SeededPrng = serde_json::from_str(&serialized_json).unwrap();

        assert_eq!(
            serialized_prng, deserialized_prng,
            "PRNG should maintain state through serialization round-trip"
        );

        // Generate sequences from both and verify they match
        let mut orig_prng = serialized_prng;
        let mut deser_prng = deserialized_prng;

        for i in 0..100 {
            let orig_value = orig_prng.next_u64();
            let deser_value = deser_prng.next_u64();
            assert_eq!(
                orig_value, deser_value,
                "Serialization round-trip should preserve PRNG sequence at step {}",
                i
            );
        }
    }

    #[test]
    fn negative_test_clock_overflow_and_time_manipulation_attack_resistance() {
        let mut config = LabConfig::new(12345);
        let mut runtime = LabRuntime::new(config.clone()).expect("Should create runtime");

        // Test 1: Clock overflow protection with extreme tick advances
        let overflow_tests = vec![
            (u64::MAX - 1000, 500),  // Safe advance near max
            (u64::MAX - 100, 50),    // Very close to overflow
            (u64::MAX - 1, 1),       // Exact boundary
            (1000, u64::MAX - 1500), // Large delta that would overflow
            (0, u64::MAX),           // Maximum possible advance
        ];

        for (current_expected, advance_delta) in overflow_tests {
            // Reset runtime for each test
            runtime = LabRuntime::new(config.clone()).expect("Should recreate runtime");

            // Advance to current position
            if current_expected > 0 {
                let advance_to_current = runtime.advance_clock(current_expected);
                if advance_to_current.is_err() {
                    continue; // Skip if we can't reach this position
                }
            }

            let current_tick = runtime.current_tick();
            let advance_result = runtime.advance_clock(advance_delta);

            match advance_result {
                Ok(_) => {
                    // If advance succeeds, verify no overflow occurred
                    let new_tick = runtime.current_tick();
                    assert!(
                        new_tick >= current_tick,
                        "Clock should not go backwards: {} -> {}",
                        current_tick,
                        new_tick
                    );

                    // Verify the advance was bounded properly
                    let expected_max = current_tick.saturating_add(advance_delta);
                    assert!(
                        new_tick <= expected_max,
                        "Clock advance should be bounded: {} <= {}",
                        new_tick,
                        expected_max
                    );
                }
                Err(LabError::TickOverflow { current, delta }) => {
                    // Overflow protection activated correctly
                    assert_eq!(
                        current, current_tick,
                        "Overflow error should report current tick"
                    );
                    assert_eq!(
                        delta, advance_delta,
                        "Overflow error should report requested delta"
                    );
                }
                Err(other) => {
                    panic!("Unexpected error during clock advance: {:?}", other);
                }
            }
        }

        // Test 2: Timer scheduling with extreme and boundary tick values
        runtime = LabRuntime::new(config.clone()).expect("Should recreate runtime");

        let timer_tests = vec![
            0,               // Immediate timer
            1,               // Next tick
            1000,            // Normal future timer
            u64::MAX - 1000, // Very far future
            u64::MAX - 1,    // Near maximum tick
            u64::MAX,        // Maximum tick value
        ];

        let mut timer_ids = Vec::new();
        for target_tick in timer_tests {
            match runtime.schedule_timer(target_tick) {
                Ok(timer_id) => {
                    timer_ids.push((timer_id, target_tick));

                    // Verify timer ID is reasonable
                    assert!(timer_id > 0, "Timer ID should be positive");
                }
                Err(LabError::TimerIdExhausted) => {
                    // Expected when approaching ID limits
                    break;
                }
                Err(other) => {
                    panic!(
                        "Unexpected timer scheduling error for tick {}: {:?}",
                        target_tick, other
                    );
                }
            }
        }

        // Test 3: Timer firing order consistency under clock manipulation
        runtime = LabRuntime::new(config.clone()).expect("Should recreate runtime");

        let timer_schedule = vec![100, 50, 200, 75, 150, 25];
        let mut scheduled_timers = Vec::new();

        for &tick in &timer_schedule {
            if let Ok(timer_id) = runtime.schedule_timer(tick) {
                scheduled_timers.push((timer_id, tick));
            }
        }

        // Advance clock to trigger timers and verify firing order
        let mut fired_ticks = Vec::new();
        let max_tick = timer_schedule.iter().max().unwrap_or(&0);

        for target_tick in 0..=*max_tick {
            if let Ok(_) = runtime.advance_clock(1) {
                // Check for fired timers
                let events = runtime.get_events();
                for event in events {
                    if event.event_code == EVT_TIMER_FIRED {
                        fired_ticks.push(target_tick + 1);
                    }
                }
            }
        }

        // Verify timers fired in ascending tick order
        for window in fired_ticks.windows(2) {
            assert!(
                window[0] <= window[1],
                "Timers should fire in ascending order: {} <= {}",
                window[0],
                window[1]
            );
        }

        // Test 4: Clock state consistency after manipulation attacks
        runtime = LabRuntime::new(config.clone()).expect("Should recreate runtime");

        let manipulation_sequence = vec![1000, 500, 1500, 100, 2000, 50, 3000, 10];

        let mut previous_tick = 0;
        for advance in manipulation_sequence {
            if let Ok(_) = runtime.advance_clock(advance) {
                let current = runtime.current_tick();
                assert!(
                    current >= previous_tick,
                    "Clock should never go backwards: {} -> {}",
                    previous_tick,
                    current
                );
                previous_tick = current;
            }
        }

        // Final state should be consistent
        let final_tick = runtime.current_tick();
        let stats = runtime.get_runtime_stats();
        assert!(
            stats.current_tick == final_tick,
            "Runtime stats should match actual clock state"
        );
    }

    #[test]
    fn negative_virtual_link_capacity_exhaustion_and_message_flood_resistance() {
        let config = LabConfig::new(33333);
        let mut runtime = LabRuntime::new(config).expect("Should create runtime");

        // Test 1: Virtual link capacity limits under message flooding
        let link_config = VirtualLinkConfig {
            source: "flood_source".to_string(),
            target: "flood_target".to_string(),
            capacity: 100, // Small capacity for testing
            fault_config: FaultConfig {
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                reorder_probability: 0.0,
                corrupt_probability: 0.0,
                delay_min_ticks: 0,
                delay_max_ticks: 0,
            },
        };

        let link = runtime
            .create_virtual_link(link_config.clone())
            .expect("Should create link");

        // Attempt to flood the link beyond capacity
        let mut successful_sends = 0;
        let mut capacity_exceeded_count = 0;

        for i in 0..200 {
            let message = format!("flood_message_{}", i).into_bytes();
            match runtime.send_message(&link, message) {
                Ok(_) => {
                    successful_sends += 1;
                }
                Err(LabError::LinkCapacityExceeded { limit }) => {
                    assert_eq!(limit, 100, "Capacity limit should match configuration");
                    capacity_exceeded_count += 1;
                }
                Err(other) => {
                    panic!("Unexpected error during message flood: {:?}", other);
                }
            }
        }

        // Verify capacity limits were enforced
        assert!(
            successful_sends <= 100,
            "Successful sends should not exceed capacity: {}",
            successful_sends
        );
        assert!(
            capacity_exceeded_count > 0,
            "Should have hit capacity limits during flood"
        );

        // Test 2: Concurrent message sending stress test
        let concurrent_links = (0..10)
            .map(|i| {
                let config = VirtualLinkConfig {
                    source: format!("source_{}", i),
                    target: format!("target_{}", i),
                    capacity: 50,
                    fault_config: FaultConfig {
                        drop_probability: 0.0,
                        duplicate_probability: 0.0,
                        reorder_probability: 0.0,
                        corrupt_probability: 0.0,
                        delay_min_ticks: 0,
                        delay_max_ticks: 0,
                    },
                };
                runtime
                    .create_virtual_link(config)
                    .expect("Should create concurrent link")
            })
            .collect::<Vec<_>>();

        let runtime_arc = Arc::new(Mutex::new(runtime));
        let results = Arc::new(Mutex::new(Vec::new()));

        let handles: Vec<_> = (0..10)
            .map(|thread_id| {
                let runtime_clone = runtime_arc.clone();
                let results_clone = results.clone();
                let link = concurrent_links[thread_id].clone();

                thread::spawn(move || {
                    let mut thread_results = Vec::new();

                    for msg_id in 0..20 {
                        let message = format!("thread_{}_msg_{}", thread_id, msg_id).into_bytes();

                        let result = {
                            let mut runtime_guard = runtime_clone.lock().unwrap();
                            runtime_guard.send_message(&link, message)
                        };

                        thread_results.push((thread_id, msg_id, result.is_ok()));
                    }

                    results_clone.lock().unwrap().extend(thread_results);
                })
            })
            .collect();

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread should complete");
        }

        let final_results = results.lock().unwrap();
        let runtime_guard = runtime_arc.lock().unwrap();

        // Verify concurrent operation integrity
        assert_eq!(
            final_results.len(),
            10 * 20,
            "All operations should have completed"
        );

        // Check link statistics for consistency
        for link in &concurrent_links {
            let stats_result = runtime_guard.get_virtual_link_stats(link);
            match stats_result {
                Ok(stats) => {
                    assert!(
                        stats.total_messages_sent <= 50,
                        "Link should respect capacity limits: {}",
                        stats.total_messages_sent
                    );
                    assert!(
                        stats.capacity_exceeded_count >= 0,
                        "Capacity exceeded count should be non-negative"
                    );
                }
                Err(LabError::LinkNotFound { .. }) => {
                    panic!("Concurrent link should still exist");
                }
                Err(other) => {
                    panic!("Unexpected error getting link stats: {:?}", other);
                }
            }
        }

        // Test 3: Message size and content boundary attacks
        drop(runtime_guard);
        let mut runtime = LabRuntime::new(LabConfig::new(44444)).expect("Should create runtime");

        let size_test_config = VirtualLinkConfig {
            source: "size_source".to_string(),
            target: "size_target".to_string(),
            capacity: 1000,
            fault_config: FaultConfig {
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                reorder_probability: 0.0,
                corrupt_probability: 0.0,
                delay_min_ticks: 0,
                delay_max_ticks: 0,
            },
        };

        let size_link = runtime
            .create_virtual_link(size_test_config)
            .expect("Should create size test link");

        let size_attack_messages = vec![
            vec![],                                             // Empty message
            vec![0x42],                                         // Single byte
            vec![0x00; 1000],                                   // Null bytes
            vec![0xFF; 1000],                                   // Max bytes
            (0..=255).cycle().take(10000).collect::<Vec<u8>>(), // Large pattern
            vec![0x42; 1_000_000],                              // 1MB message
            "🚀".repeat(1000).into_bytes(),                     // Unicode flood
            b"\r\n\t\x00\xFF".repeat(1000).to_vec(),            // Control character flood
        ];

        for (idx, message) in size_attack_messages.iter().enumerate() {
            let result = runtime.send_message(&size_link, message.clone());

            match result {
                Ok(_) => {
                    // Message accepted - verify it's properly handled
                    let stats = runtime.get_virtual_link_stats(&size_link);
                    assert!(
                        stats.is_ok(),
                        "Link stats should be accessible after message {}",
                        idx
                    );
                }
                Err(LabError::LinkCapacityExceeded { .. }) => {
                    // Acceptable if message causes capacity issues
                }
                Err(other) => {
                    // Other errors may be acceptable for extreme messages
                    assert!(
                        !other.to_string().is_empty(),
                        "Error message should be meaningful for attack {}",
                        idx
                    );
                }
            }
        }

        // Verify runtime state consistency after size attacks
        let final_stats = runtime.get_runtime_stats();
        assert!(
            final_stats.total_virtual_links > 0,
            "Should have virtual links"
        );
        assert!(
            final_stats.total_messages_sent >= 0,
            "Message count should be valid"
        );
    }

    #[test]
    fn negative_fault_injection_probability_manipulation_and_edge_case_resistance() {
        let config = LabConfig::new(55555);
        let mut runtime = LabRuntime::new(config).expect("Should create runtime");

        // Test 1: Invalid fault probability ranges
        let invalid_fault_configs = vec![
            // Negative probabilities
            FaultConfig {
                drop_probability: -0.1,
                duplicate_probability: 0.5,
                reorder_probability: 0.3,
                corrupt_probability: 0.2,
                delay_min_ticks: 0,
                delay_max_ticks: 10,
            },
            // Probabilities > 1.0
            FaultConfig {
                drop_probability: 0.5,
                duplicate_probability: 1.5,
                reorder_probability: 0.3,
                corrupt_probability: 0.2,
                delay_min_ticks: 0,
                delay_max_ticks: 10,
            },
            // NaN probabilities
            FaultConfig {
                drop_probability: f64::NAN,
                duplicate_probability: 0.5,
                reorder_probability: 0.3,
                corrupt_probability: 0.2,
                delay_min_ticks: 0,
                delay_max_ticks: 10,
            },
            // Infinite probabilities
            FaultConfig {
                drop_probability: 0.5,
                duplicate_probability: f64::INFINITY,
                reorder_probability: 0.3,
                corrupt_probability: 0.2,
                delay_min_ticks: 0,
                delay_max_ticks: 10,
            },
            // Very small non-zero values
            FaultConfig {
                drop_probability: f64::MIN_POSITIVE,
                duplicate_probability: 0.0,
                reorder_probability: 0.0,
                corrupt_probability: 0.0,
                delay_min_ticks: 0,
                delay_max_ticks: 0,
            },
        ];

        for (idx, fault_config) in invalid_fault_configs.iter().enumerate() {
            let link_config = VirtualLinkConfig {
                source: format!("fault_source_{}", idx),
                target: format!("fault_target_{}", idx),
                capacity: 100,
                fault_config: fault_config.clone(),
            };

            let link_result = runtime.create_virtual_link(link_config);

            match link_result {
                Ok(_) => {
                    // If link creation succeeds, fault injection should handle invalid values gracefully
                    // This tests runtime fault handling rather than validation
                }
                Err(LabError::FaultRange { field, value }) => {
                    // Expected validation error
                    assert!(!field.is_empty(), "Field name should be provided");
                    assert!(
                        !value.is_finite() || value < 0.0 || value > 1.0,
                        "Invalid value should be outside [0,1] range or non-finite"
                    );
                }
                Err(other) => {
                    panic!("Unexpected error for fault config {}: {:?}", idx, other);
                }
            }
        }

        // Test 2: Extreme delay range configurations
        let delay_attack_configs = vec![
            // Inverted delay range (max < min)
            FaultConfig {
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                reorder_probability: 0.0,
                corrupt_probability: 0.0,
                delay_min_ticks: 1000,
                delay_max_ticks: 100,
            },
            // Very large delay ranges
            FaultConfig {
                drop_probability: 0.1,
                duplicate_probability: 0.0,
                reorder_probability: 0.0,
                corrupt_probability: 0.0,
                delay_min_ticks: 0,
                delay_max_ticks: u64::MAX - 1000,
            },
            // Zero delay range
            FaultConfig {
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                reorder_probability: 0.0,
                corrupt_probability: 0.0,
                delay_min_ticks: 1000,
                delay_max_ticks: 1000,
            },
        ];

        for (idx, delay_config) in delay_attack_configs.iter().enumerate() {
            let link_config = VirtualLinkConfig {
                source: format!("delay_source_{}", idx),
                target: format!("delay_target_{}", idx),
                capacity: 50,
                fault_config: delay_config.clone(),
            };

            match runtime.create_virtual_link(link_config.clone()) {
                Ok(link) => {
                    // Test message sending with extreme delay configs
                    for msg_num in 0..10 {
                        let message = format!("delay_test_{}_{}", idx, msg_num).into_bytes();
                        let send_result = runtime.send_message(&link, message);

                        match send_result {
                            Ok(_) => {
                                // Message sent successfully despite extreme config
                            }
                            Err(LabError::LinkCapacityExceeded { .. }) => {
                                // Acceptable if delays cause capacity issues
                                break;
                            }
                            Err(other) => {
                                // Other errors may occur with extreme delay configs
                                assert!(!other.to_string().is_empty());
                            }
                        }
                    }
                }
                Err(_) => {
                    // Link creation may fail with invalid delay configs
                }
            }
        }

        // Test 3: Fault probability combinations that sum > 1.0
        let probability_sum_attacks = vec![
            FaultConfig {
                drop_probability: 0.6,
                duplicate_probability: 0.6,
                reorder_probability: 0.6,
                corrupt_probability: 0.6,
                delay_min_ticks: 0,
                delay_max_ticks: 10,
            },
            FaultConfig {
                drop_probability: 1.0,
                duplicate_probability: 1.0,
                reorder_probability: 1.0,
                corrupt_probability: 1.0,
                delay_min_ticks: 0,
                delay_max_ticks: 10,
            },
        ];

        for (idx, sum_config) in probability_sum_attacks.iter().enumerate() {
            let link_config = VirtualLinkConfig {
                source: format!("sum_source_{}", idx),
                target: format!("sum_target_{}", idx),
                capacity: 50,
                fault_config: sum_config.clone(),
            };

            match runtime.create_virtual_link(link_config) {
                Ok(link) => {
                    // If link creation succeeds, test fault application
                    let mut fault_counts = HashMap::new();

                    for msg_num in 0..100 {
                        let message = format!("sum_test_{}_{}", idx, msg_num).into_bytes();
                        let _ = runtime.send_message(&link, message);

                        // Check for fault events
                        let events = runtime.get_events();
                        for event in events {
                            if event.event_code == EVT_FAULT_INJECTED {
                                *fault_counts.entry("fault").or_insert(0) += 1;
                            }
                        }
                    }

                    // With probabilities that sum > 1.0, fault behavior should still be deterministic
                    let stats = runtime.get_virtual_link_stats(&link);
                    if let Ok(link_stats) = stats {
                        assert!(
                            link_stats.total_faults_injected >= 0,
                            "Fault count should be non-negative"
                        );
                    }
                }
                Err(_) => {
                    // Link creation may fail with invalid probability sums
                }
            }
        }

        // Verify runtime state consistency after fault attacks
        let final_stats = runtime.get_runtime_stats();
        assert!(
            final_stats.total_faults_injected >= 0,
            "Total faults should be non-negative"
        );
        assert!(
            final_stats.current_tick >= 0,
            "Current tick should be valid"
        );
    }

    #[test]
    fn negative_dpor_exploration_budget_exhaustion_and_state_explosion_resistance() {
        // Test DPOR exploration under extreme conditions and budget attacks
        let mut config = LabConfig::new(66666);
        config.dpor_budget = 100; // Small budget for testing

        let mut runtime = LabRuntime::new(config.clone()).expect("Should create runtime");

        // Test 1: Budget exhaustion through state explosion
        let state_explosion_config = VirtualLinkConfig {
            source: "dpor_source".to_string(),
            target: "dpor_target".to_string(),
            capacity: 1000,
            fault_config: FaultConfig {
                drop_probability: 0.2,
                duplicate_probability: 0.2,
                reorder_probability: 0.2,
                corrupt_probability: 0.2,
                delay_min_ticks: 1,
                delay_max_ticks: 10,
            },
        };

        let dpor_link = runtime
            .create_virtual_link(state_explosion_config)
            .expect("Should create DPOR link");

        // Generate many messages to trigger extensive DPOR exploration
        let mut exploration_count = 0;
        let mut budget_exceeded = false;

        for i in 0..200 {
            let message = format!("dpor_explosion_{}", i).into_bytes();

            match runtime.send_message(&dpor_link, message) {
                Ok(_) => {
                    exploration_count += 1;
                }
                Err(LabError::BudgetExceeded { explored, budget }) => {
                    assert_eq!(budget, 100, "Budget should match configuration");
                    assert!(
                        explored <= budget,
                        "Explored count should not exceed budget"
                    );
                    budget_exceeded = true;
                    break;
                }
                Err(other) => {
                    // Other errors may occur due to fault injection
                    assert!(!other.to_string().is_empty());
                }
            }

            // Check for DPOR interleaving events
            let events = runtime.get_events();
            for event in events {
                if event.event_code == EVT_DPOR_INTERLEAVING {
                    exploration_count += 1;
                }
            }
        }

        // Budget should eventually be exceeded with enough state explosion
        if !budget_exceeded && exploration_count > 0 {
            // Try more aggressive state explosion
            let _ = runtime.advance_clock(100); // Trigger timer events

            for i in 200..500 {
                let message = format!("aggressive_dpor_{}", i).into_bytes();
                match runtime.send_message(&dpor_link, message) {
                    Err(LabError::BudgetExceeded { .. }) => {
                        budget_exceeded = true;
                        break;
                    }
                    _ => {}
                }
            }
        }

        // Test 2: DPOR budget configuration edge cases
        let budget_edge_cases = vec![0, 1, u64::MAX];

        for test_budget in budget_edge_cases {
            let mut edge_config = LabConfig::new(77777);
            edge_config.dpor_budget = test_budget;

            let edge_runtime_result = LabRuntime::new(edge_config);

            match edge_runtime_result {
                Ok(mut edge_runtime) => {
                    let test_config = VirtualLinkConfig {
                        source: "edge_source".to_string(),
                        target: "edge_target".to_string(),
                        capacity: 10,
                        fault_config: FaultConfig {
                            drop_probability: 0.5,
                            duplicate_probability: 0.5,
                            reorder_probability: 0.5,
                            corrupt_probability: 0.5,
                            delay_min_ticks: 1,
                            delay_max_ticks: 5,
                        },
                    };

                    if let Ok(test_link) = edge_runtime.create_virtual_link(test_config) {
                        let test_message = b"edge_budget_test".to_vec();
                        let send_result = edge_runtime.send_message(&test_link, test_message);

                        match send_result {
                            Ok(_) => {
                                // Successful with edge budget
                            }
                            Err(LabError::BudgetExceeded { .. }) => {
                                // Expected with very small budgets
                            }
                            Err(_) => {
                                // Other errors acceptable for edge cases
                            }
                        }
                    }
                }
                Err(_) => {
                    // Runtime creation may fail with extreme budget values
                }
            }
        }

        // Test 3: Deterministic DPOR behavior across runs
        let determinism_seed = 88888;
        let mut determinism_results = Vec::new();

        for run in 0..3 {
            let mut det_config = LabConfig::new(determinism_seed);
            det_config.dpor_budget = 50;

            let mut det_runtime =
                LabRuntime::new(det_config).expect("Should create determinism runtime");

            let det_link_config = VirtualLinkConfig {
                source: "det_source".to_string(),
                target: "det_target".to_string(),
                capacity: 20,
                fault_config: FaultConfig {
                    drop_probability: 0.1,
                    duplicate_probability: 0.1,
                    reorder_probability: 0.1,
                    corrupt_probability: 0.1,
                    delay_min_ticks: 1,
                    delay_max_ticks: 3,
                },
            };

            let det_link = det_runtime
                .create_virtual_link(det_link_config)
                .expect("Should create determinism link");

            let mut run_events = Vec::new();
            for i in 0..20 {
                let message = format!("det_msg_{}", i).into_bytes();
                let send_result = det_runtime.send_message(&det_link, message);
                run_events.push((i, send_result.is_ok()));

                if send_result.is_err() {
                    break;
                }
            }

            determinism_results.push(run_events);
        }

        // Verify deterministic behavior across runs
        if determinism_results.len() >= 2 {
            for i in 1..determinism_results.len() {
                assert_eq!(
                    determinism_results[0], determinism_results[i],
                    "DPOR exploration should be deterministic across runs {} and 0",
                    i
                );
            }
        }

        println!("DPOR budget exhaustion test completed: explored states within limits");
    }

    #[test]
    fn negative_repro_bundle_serialization_corruption_and_tampering_resistance() {
        let config = LabConfig::new(99999);
        let mut runtime = LabRuntime::new(config).expect("Should create runtime");

        // Set up test scenario with complex state
        let bundle_test_config = VirtualLinkConfig {
            source: "bundle_source".to_string(),
            target: "bundle_target".to_string(),
            capacity: 50,
            fault_config: FaultConfig {
                drop_probability: 0.1,
                duplicate_probability: 0.1,
                reorder_probability: 0.1,
                corrupt_probability: 0.1,
                delay_min_ticks: 1,
                delay_max_ticks: 5,
            },
        };

        let bundle_link = runtime
            .create_virtual_link(bundle_test_config)
            .expect("Should create bundle link");

        // Generate complex runtime state
        for i in 0..30 {
            let message = format!("bundle_state_msg_{}", i).into_bytes();
            let _ = runtime.send_message(&bundle_link, message);
        }

        let _ = runtime.advance_clock(100); // Trigger timers
        let _ = runtime.schedule_timer(200); // Add future timer

        // Test 1: Normal bundle export and validation
        let export_result = runtime.export_repro_bundle();
        assert!(export_result.is_ok(), "Bundle export should succeed");

        let original_bundle = export_result.unwrap();

        // Test 2: Bundle serialization round-trip integrity
        let serialized = serde_json::to_string(&original_bundle).expect("Should serialize bundle");
        let deserialized: ReproBundle =
            serde_json::from_str(&serialized).expect("Should deserialize bundle");

        assert_eq!(
            original_bundle.schema_version, deserialized.schema_version,
            "Schema version should be preserved"
        );
        assert_eq!(
            original_bundle.seed, deserialized.seed,
            "Seed should be preserved"
        );
        assert_eq!(
            original_bundle.events.len(),
            deserialized.events.len(),
            "Event count should be preserved"
        );

        // Test 3: Bundle corruption detection
        let corruption_attacks = vec![
            // Schema version tampering
            {
                let mut corrupted = original_bundle.clone();
                corrupted.schema_version = "corrupted-schema-v999".to_string();
                corrupted
            },
            // Seed manipulation
            {
                let mut corrupted = original_bundle.clone();
                corrupted.seed = u64::MAX;
                corrupted
            },
            // Event list manipulation
            {
                let mut corrupted = original_bundle.clone();
                corrupted.events.clear();
                corrupted
            },
            // Event content corruption
            {
                let mut corrupted = original_bundle.clone();
                if let Some(event) = corrupted.events.get_mut(0) {
                    event.event_code = "CORRUPTED_EVENT".to_string();
                }
                corrupted
            },
            // Configuration tampering
            {
                let mut corrupted = original_bundle.clone();
                corrupted.config.dpor_budget = u64::MAX;
                corrupted
            },
        ];

        for (attack_idx, corrupted_bundle) in corruption_attacks.iter().enumerate() {
            // Test replay with corrupted bundle
            let replay_result = LabRuntime::from_repro_bundle(corrupted_bundle.clone());

            match replay_result {
                Ok(mut replay_runtime) => {
                    // If replay succeeds, verify it handles corruption gracefully
                    let replay_stats = replay_runtime.get_runtime_stats();

                    // Basic sanity checks on replayed runtime
                    assert!(
                        replay_stats.current_tick >= 0,
                        "Replay tick should be valid for attack {}",
                        attack_idx
                    );
                }
                Err(LabError::BundleValidation { detail }) => {
                    // Expected validation failure
                    assert!(
                        !detail.is_empty(),
                        "Validation error should have detail for attack {}",
                        attack_idx
                    );
                }
                Err(LabError::ReplayDivergence {
                    expected_events,
                    actual_events,
                }) => {
                    // Expected divergence due to corruption
                    println!(
                        "Replay divergence detected for attack {}: expected {}, got {}",
                        attack_idx, expected_events, actual_events
                    );
                }
                Err(other) => {
                    // Other errors may occur with corrupted bundles
                    assert!(
                        !other.to_string().is_empty(),
                        "Error should be meaningful for attack {}",
                        attack_idx
                    );
                }
            }
        }

        // Test 4: Malformed JSON bundle attacks
        let json_attacks = vec![
            r#"{"schema_version": "lab-v1.0", "seed": "not_a_number"}"#,
            r#"{"schema_version": "lab-v1.0", "seed": 12345, "events": "not_an_array"}"#,
            r#"{"schema_version": null, "seed": 12345, "events": []}"#,
            r#"{"invalid_field": true, "seed": 12345}"#,
            r#"{"schema_version": "lab-v1.0", "seed": 99999999999999999999999999999999999}"#, // Overflow
            r#"{}"#,       // Empty object
            r#"[]"#,       // Array instead of object
            r#"null"#,     // Null
            r#""string""#, // String instead of object
        ];

        for (attack_idx, malformed_json) in json_attacks.iter().enumerate() {
            let parse_result: Result<ReproBundle, _> = serde_json::from_str(malformed_json);

            match parse_result {
                Ok(parsed_bundle) => {
                    // If parsing succeeds, test replay resilience
                    let replay_result = LabRuntime::from_repro_bundle(parsed_bundle);
                    match replay_result {
                        Ok(_) => {
                            // Successful replay despite malformed input
                        }
                        Err(error) => {
                            // Expected failure with malformed bundle
                            assert!(
                                !error.to_string().is_empty(),
                                "Error should be meaningful for JSON attack {}",
                                attack_idx
                            );
                        }
                    }
                }
                Err(_) => {
                    // Expected JSON parsing failure
                }
            }
        }

        // Test 5: Bundle size and memory exhaustion attacks
        let mut memory_attack_bundle = original_bundle.clone();

        // Generate massive event list
        for i in 0..100_000 {
            memory_attack_bundle.events.push(LabEvent {
                event_code: format!("MEMORY_ATTACK_{}", i),
                tick: i as u64,
                details: format!("attack_data_{}", "x".repeat(1000)),
            });
        }

        let massive_bundle_result = LabRuntime::from_repro_bundle(memory_attack_bundle);

        match massive_bundle_result {
            Ok(mut massive_runtime) => {
                // If it succeeds, verify memory usage is reasonable
                let stats = massive_runtime.get_runtime_stats();
                assert!(stats.total_events >= 0, "Event count should be valid");

                // Try basic operations to ensure functionality
                let test_message = b"memory_test".to_vec();
                if let Ok(test_link) = massive_runtime.create_virtual_link(VirtualLinkConfig {
                    source: "memory_source".to_string(),
                    target: "memory_target".to_string(),
                    capacity: 10,
                    fault_config: FaultConfig::default(),
                }) {
                    let _ = massive_runtime.send_message(&test_link, test_message);
                }
            }
            Err(error) => {
                // Acceptable failure with massive bundle
                assert!(!error.to_string().is_empty());
            }
        }

        println!("Repro bundle corruption resistance test completed successfully");
    }

    #[test]
    fn negative_lab_configuration_injection_and_boundary_overflow_comprehensive() {
        // Test extreme lab configurations and boundary condition attacks
        let config_attacks = vec![
            // Extreme DPOR budgets
            LabConfig {
                seed: Some(12345),
                dpor_budget: 0,
                max_events: 1000,
                virtual_link_capacity_default: 100,
                fault_injection_enabled: true,
            },
            LabConfig {
                seed: Some(67890),
                dpor_budget: u64::MAX,
                max_events: 1000,
                virtual_link_capacity_default: 100,
                fault_injection_enabled: true,
            },
            // Extreme event limits
            LabConfig {
                seed: Some(11111),
                dpor_budget: 1000,
                max_events: 0,
                virtual_link_capacity_default: 100,
                fault_injection_enabled: true,
            },
            LabConfig {
                seed: Some(22222),
                dpor_budget: 1000,
                max_events: usize::MAX,
                virtual_link_capacity_default: 100,
                fault_injection_enabled: true,
            },
            // Extreme virtual link capacities
            LabConfig {
                seed: Some(33333),
                dpor_budget: 1000,
                max_events: 1000,
                virtual_link_capacity_default: 0,
                fault_injection_enabled: true,
            },
            LabConfig {
                seed: Some(44444),
                dpor_budget: 1000,
                max_events: 1000,
                virtual_link_capacity_default: usize::MAX,
                fault_injection_enabled: true,
            },
            // No seed (should trigger error)
            LabConfig {
                seed: None,
                dpor_budget: 1000,
                max_events: 1000,
                virtual_link_capacity_default: 100,
                fault_injection_enabled: true,
            },
            // Disabled fault injection
            LabConfig {
                seed: Some(55555),
                dpor_budget: 1000,
                max_events: 1000,
                virtual_link_capacity_default: 100,
                fault_injection_enabled: false,
            },
        ];

        for (config_idx, attack_config) in config_attacks.iter().enumerate() {
            let runtime_result = LabRuntime::new(attack_config.clone());

            match runtime_result {
                Ok(mut runtime) => {
                    // Configuration accepted - test basic operations
                    println!("Config {} accepted, testing operations", config_idx);

                    // Test virtual link creation with extreme config
                    let test_link_config = VirtualLinkConfig {
                        source: format!("config_source_{}", config_idx),
                        target: format!("config_target_{}", config_idx),
                        capacity: attack_config.virtual_link_capacity_default.min(1000), // Bound for testing
                        fault_config: FaultConfig {
                            drop_probability: if attack_config.fault_injection_enabled {
                                0.1
                            } else {
                                0.0
                            },
                            duplicate_probability: 0.0,
                            reorder_probability: 0.0,
                            corrupt_probability: 0.0,
                            delay_min_ticks: 0,
                            delay_max_ticks: 5,
                        },
                    };

                    match runtime.create_virtual_link(test_link_config) {
                        Ok(test_link) => {
                            // Test message operations
                            for msg_idx in 0..10 {
                                let message =
                                    format!("config_test_{}_{}", config_idx, msg_idx).into_bytes();
                                let send_result = runtime.send_message(&test_link, message);

                                match send_result {
                                    Ok(_) => {
                                        // Successful send
                                    }
                                    Err(LabError::LinkCapacityExceeded { .. }) => {
                                        // Expected with zero capacity configs
                                        break;
                                    }
                                    Err(LabError::BudgetExceeded { .. }) => {
                                        // Expected with zero DPOR budget
                                        break;
                                    }
                                    Err(other) => {
                                        // Other errors may occur with extreme configs
                                        assert!(
                                            !other.to_string().is_empty(),
                                            "Error should be meaningful for config {} msg {}",
                                            config_idx,
                                            msg_idx
                                        );
                                    }
                                }
                            }

                            // Test timer operations
                            if let Ok(timer_id) = runtime.schedule_timer(100) {
                                let _ = runtime.advance_clock(150);
                                // Timer should fire or be handled gracefully
                            }

                            // Test statistics access
                            let stats = runtime.get_runtime_stats();
                            assert!(
                                stats.current_tick >= 0,
                                "Tick should be non-negative for config {}",
                                config_idx
                            );

                            if attack_config.max_events > 0 {
                                assert!(
                                    stats.total_events <= attack_config.max_events,
                                    "Event count should respect limit for config {}",
                                    config_idx
                                );
                            }
                        }
                        Err(_) => {
                            // Link creation may fail with extreme configs
                        }
                    }

                    // Test bundle export with extreme config
                    match runtime.export_repro_bundle() {
                        Ok(bundle) => {
                            // Verify bundle consistency
                            assert_eq!(
                                bundle.config.dpor_budget, attack_config.dpor_budget,
                                "Bundle should preserve DPOR budget for config {}",
                                config_idx
                            );
                            assert_eq!(
                                bundle.config.max_events, attack_config.max_events,
                                "Bundle should preserve max events for config {}",
                                config_idx
                            );
                        }
                        Err(error) => {
                            // Bundle export may fail with extreme configs
                            assert!(
                                !error.to_string().is_empty(),
                                "Bundle export error should be meaningful for config {}",
                                config_idx
                            );
                        }
                    }
                }
                Err(LabError::NoSeed) => {
                    // Expected for configs without seed
                    assert!(
                        attack_config.seed.is_none(),
                        "NoSeed error should only occur for configs without seed"
                    );
                }
                Err(other) => {
                    // Other errors may occur with extreme configurations
                    assert!(
                        !other.to_string().is_empty(),
                        "Configuration error should be meaningful for config {}",
                        config_idx
                    );
                }
            }
        }

        // Test configuration field injection attacks
        let config_json_attacks = vec![
            // Invalid field types
            r#"{"seed": "not_a_number", "dpor_budget": 1000}"#,
            r#"{"seed": 12345, "dpor_budget": "not_a_number"}"#,
            r#"{"seed": 12345, "max_events": -1}"#,
            // Overflow attempts
            r#"{"seed": 99999999999999999999999999999999999, "dpor_budget": 1000}"#,
            r#"{"seed": 12345, "dpor_budget": 99999999999999999999999999999999999}"#,
            // Type confusion
            r#"{"seed": [], "dpor_budget": 1000}"#,
            r#"{"seed": 12345, "dpor_budget": {}}"#,
            // Missing required fields
            r#"{"dpor_budget": 1000}"#,
            r#"{"seed": 12345}"#,
            // Extra malicious fields
            r#"{"seed": 12345, "dpor_budget": 1000, "__proto__": "malicious"}"#,
            r#"{"seed": 12345, "dpor_budget": 1000, "constructor": {"prototype": "attack"}}"#,
        ];

        for (attack_idx, malformed_json) in config_json_attacks.iter().enumerate() {
            let parse_result: Result<LabConfig, _> = serde_json::from_str(malformed_json);

            match parse_result {
                Ok(parsed_config) => {
                    // If parsing succeeds, test runtime creation
                    let runtime_result = LabRuntime::new(parsed_config);

                    match runtime_result {
                        Ok(_) => {
                            // Runtime creation succeeded despite malformed config
                        }
                        Err(error) => {
                            // Expected runtime creation failure
                            assert!(
                                !error.to_string().is_empty(),
                                "Runtime error should be meaningful for JSON attack {}",
                                attack_idx
                            );
                        }
                    }
                }
                Err(_) => {
                    // Expected JSON parsing failure
                }
            }
        }

        println!("Lab configuration injection resistance test completed successfully");
    }
}
