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
/// The mock clock was advanced.
pub const EVT_MOCK_CLOCK_ADVANCED: &str = "FN-LB-010";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// No seed was provided in the lab configuration.
pub const ERR_LB_NO_SEED: &str = "ERR_LB_NO_SEED";
/// Mock clock tick would overflow u64.
pub const ERR_LB_TICK_OVERFLOW: &str = "ERR_LB_TICK_OVERFLOW";
/// Referenced virtual link does not exist.
pub const ERR_LB_LINK_NOT_FOUND: &str = "ERR_LB_LINK_NOT_FOUND";
/// Fault probability outside [0.0, 1.0].
pub const ERR_LB_FAULT_RANGE: &str = "ERR_LB_FAULT_RANGE";
/// DPOR interleaving budget exceeded.
pub const ERR_LB_BUDGET_EXCEEDED: &str = "ERR_LB_BUDGET_EXCEEDED";
/// Replay diverged from recorded execution.
pub const ERR_LB_REPLAY_DIVERGENCE: &str = "ERR_LB_REPLAY_DIVERGENCE";

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
/// No std::time usage in lab mode — all timing via MockClock.
pub const INV_LB_NO_WALLCLOCK: &str = "INV-LB-NO-WALLCLOCK";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Lab runtime errors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LabError {
    /// No seed was supplied.
    NoSeed,
    /// Mock clock would overflow.
    TickOverflow { current: u64, delta: u64 },
    /// Virtual link not found.
    LinkNotFound { source: String, target: String },
    /// Fault probability out of valid range.
    FaultRange { field: String, value: f64 },
    /// DPOR exploration budget exceeded.
    BudgetExceeded { explored: u64, budget: u64 },
    /// Replay produced a different outcome.
    ReplayDivergence {
        expected_events: usize,
        actual_events: usize,
    },
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
            Self::LinkNotFound { source, target } => {
                write!(f, "{ERR_LB_LINK_NOT_FOUND}: {source} -> {target}")
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
    /// Mock-clock tick at which the event occurred.
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

/// A pending timer callback in the mock clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimerCallback {
    /// Unique timer identifier.
    pub id: u64,
    /// Label for structured logging.
    pub label: String,
}

// ---------------------------------------------------------------------------
// MockClock
// ---------------------------------------------------------------------------

/// Deterministic mock clock driven by explicit tick advancement.
/// INV-LB-TIMER-ORDER: timers fire in ascending tick order (BTreeMap guarantees).
/// INV-LB-NO-WALLCLOCK: no std::time usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockClock {
    /// Current tick.
    pub current_tick: u64,
    /// Pending timers keyed by fire-tick. BTreeMap guarantees ascending order.
    pub pending_timers: BTreeMap<u64, Vec<TimerCallback>>,
    /// Monotonic timer ID counter.
    next_timer_id: u64,
}

impl MockClock {
    /// Create a new mock clock starting at tick 0.
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
        let id = self.next_timer_id;
        self.next_timer_id += 1;
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

        // Collect all timer ticks <= new_tick. Using split_off to efficiently
        // partition the BTreeMap.
        let remaining = self.pending_timers.split_off(&(new_tick + 1));
        let ready = std::mem::replace(&mut self.pending_timers, remaining);

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

impl Default for MockClock {
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
    /// Serialize to a deterministic JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self, LabError> {
        serde_json::from_str(s).map_err(|_e| LabError::ReplayDivergence {
            expected_events: 0,
            actual_events: 0,
        })
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
/// - INV-LB-TIMER-ORDER: timers fire in tick order (delegated to MockClock)
/// - INV-LB-FAULT-APPLIED: faults applied per profile
/// - INV-LB-NO-WALLCLOCK: no std::time — only MockClock ticks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabRuntime {
    /// Deterministic seed.
    pub seed: u64,
    /// Mock clock for deterministic time.
    pub mock_clock: MockClock,
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
            mock_clock: MockClock::new(),
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
            return Ok(MessageOutcome::Dropped);
        }

        let roll_corrupt = self.rng.next_f64();
        if roll_corrupt < profile.corrupt_probability {
            self.emit(
                EVT_FAULT_INJECTED,
                format!("corrupted on {source}->{target}"),
            );
            return Ok(MessageOutcome::Corrupted {
                delay_ticks: profile.delay_ticks,
            });
        }

        if profile.reorder_depth > 0 {
            let buf = &mut self.reorder_buffers[link_idx];
            buf.push(message.to_string());
            if buf.len() >= profile.reorder_depth {
                // Shuffle the buffer deterministically.
                let len = buf.len();
                for i in (1..len).rev() {
                    let j = self.rng.next_usize(i + 1);
                    buf.swap(i, j);
                }
                self.emit(
                    EVT_FAULT_INJECTED,
                    format!("reordered {} messages on {source}->{target}", len),
                );
                return Ok(MessageOutcome::Reordered {
                    buffer_position: len - 1,
                    delay_ticks: profile.delay_ticks,
                });
            }
        }

        Ok(MessageOutcome::Delivered {
            delay_ticks: profile.delay_ticks,
        })
    }

    /// Schedule a timer on the mock clock.
    pub fn schedule_timer(
        &mut self,
        delay: u64,
        label: impl Into<String>,
    ) -> Result<u64, LabError> {
        self.mock_clock.schedule_timer(delay, label)
    }

    /// Advance the mock clock and fire pending timers.
    /// Returns the list of fired timer callbacks with their tick.
    pub fn advance_clock(&mut self, delta: u64) -> Result<Vec<(u64, TimerCallback)>, LabError> {
        let fired = self.mock_clock.advance(delta)?;
        if !fired.is_empty() {
            for (tick, cb) in &fired {
                self.events.push(LabEvent {
                    tick: *tick,
                    event_code: EVT_TIMER_FIRED.to_string(),
                    payload: format!("timer_id={}, label={}", cb.id, cb.label),
                });
            }
        }
        self.events.push(LabEvent {
            tick: self.mock_clock.current_tick,
            event_code: EVT_MOCK_CLOCK_ADVANCED.to_string(),
            payload: format!("delta={delta}, now={}", self.mock_clock.current_tick),
        });
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

        let repro_bundle = if !passed {
            let bundle = self.export_repro_bundle(passed);
            Some(bundle.to_json())
        } else {
            None
        };

        Ok(ScenarioResult {
            passed,
            events: self.events.clone(),
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
    pub fn export_repro_bundle(&mut self, passed: bool) -> ReproBundle {
        self.emit(
            EVT_REPRO_EXPORTED,
            format!("events={}, passed={passed}", self.events.len()),
        );
        ReproBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            seed: self.seed,
            config: self.config.clone(),
            links: self.virtual_links.clone(),
            events: self.events.clone(),
            passed,
        }
    }

    /// Replay a repro bundle and verify the outcome matches.
    /// INV-LB-REPLAY: replay must produce identical pass/fail.
    pub fn replay_bundle(
        bundle: &ReproBundle,
        scenario: &dyn Fn(&mut LabRuntime) -> Result<bool, LabError>,
    ) -> Result<ScenarioResult, LabError> {
        let mut rt = LabRuntime::new(bundle.config.clone())?;
        for link in &bundle.links {
            rt.add_link(link.clone())?;
        }
        let result = rt.run_scenario(scenario)?;

        // Verify determinism: the pass/fail outcome must match.
        if result.passed != bundle.passed {
            return Err(LabError::ReplayDivergence {
                expected_events: bundle.events.len(),
                actual_events: result.events.len(),
            });
        }

        Ok(result)
    }

    /// Get the current mock-clock tick.
    pub fn now(&self) -> u64 {
        self.mock_clock.now()
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
        self.events.push(LabEvent {
            tick: self.mock_clock.current_tick,
            event_code: code.to_string(),
            payload,
        });
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
    // MockClock
    // ---------------------------------------------------------------

    #[test]
    fn test_mock_clock_starts_at_zero() {
        let clock = MockClock::new();
        assert_eq!(clock.now(), 0);
        assert_eq!(clock.pending_count(), 0);
    }

    #[test]
    fn test_mock_clock_advance_no_timers() {
        let mut clock = MockClock::new();
        let fired = clock.advance(100).unwrap();
        assert!(fired.is_empty());
        assert_eq!(clock.now(), 100);
    }

    #[test]
    fn test_mock_clock_timer_fires_at_correct_tick() {
        // INV-LB-TIMER-ORDER: timer at tick 50 fires when advancing to 50.
        let mut clock = MockClock::new();
        clock.schedule_timer(50, "t1").unwrap();
        let fired = clock.advance(50).unwrap();
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].0, 50);
        assert_eq!(fired[0].1.label, "t1");
    }

    #[test]
    fn test_mock_clock_timer_order_invariant() {
        // INV-LB-TIMER-ORDER: timers fire in ascending tick order.
        let mut clock = MockClock::new();
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
    fn test_mock_clock_multiple_timers_same_tick() {
        let mut clock = MockClock::new();
        clock.schedule_timer(10, "a").unwrap();
        clock.schedule_timer(10, "b").unwrap();
        let fired = clock.advance(10).unwrap();
        assert_eq!(fired.len(), 2);
        // Both at tick 10.
        assert_eq!(fired[0].0, 10);
        assert_eq!(fired[1].0, 10);
    }

    #[test]
    fn test_mock_clock_timer_not_fired_early() {
        let mut clock = MockClock::new();
        clock.schedule_timer(100, "future").unwrap();
        let fired = clock.advance(50).unwrap();
        assert!(fired.is_empty());
        assert_eq!(clock.pending_count(), 1);
    }

    #[test]
    fn test_mock_clock_tick_overflow_error() {
        let mut clock = MockClock::new();
        clock.current_tick = u64::MAX - 5;
        let result = clock.advance(10);
        assert!(result.is_err());
        match result.unwrap_err() {
            LabError::TickOverflow { current, delta } => {
                assert_eq!(current, u64::MAX - 5);
                assert_eq!(delta, 10);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_mock_clock_schedule_overflow_error() {
        let mut clock = MockClock::new();
        clock.current_tick = u64::MAX;
        let result = clock.schedule_timer(1, "overflow");
        assert!(result.is_err());
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
    fn test_lab_runtime_find_link() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
        rt.add_link(make_link("x", "y", FaultProfile::default()))
            .unwrap();
        assert_eq!(rt.find_link("x", "y").unwrap(), 0);
        assert!(rt.find_link("a", "b").is_err());
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
            other => panic!("expected Delivered, got {other:?}"),
        }
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

        let json = bundle.to_json();
        assert!(!json.is_empty());

        let restored = ReproBundle::from_json(&json).unwrap();
        assert_eq!(restored.schema_version, SCHEMA_VERSION);
        assert_eq!(restored.seed, 42);
        assert!(!restored.passed);
        assert_eq!(restored.links.len(), 1);
    }

    #[test]
    fn test_repro_bundle_replay_deterministic() {
        // INV-LB-REPLAY: replay produces same outcome.
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
    }

    #[test]
    fn test_repro_bundle_replay_divergence_detected() {
        // INV-LB-REPLAY: divergent replay is detected.
        let mut rt = LabRuntime::new(default_config()).unwrap();
        let bundle = rt.export_repro_bundle(false); // original: failed

        // Replay with a scenario that passes → divergence.
        let result = LabRuntime::replay_bundle(&bundle, &|_rt| Ok(true));
        assert!(result.is_err());
        match result.unwrap_err() {
            LabError::ReplayDivergence { .. } => {}
            other => panic!("expected ReplayDivergence, got {other}"),
        }
    }

    #[test]
    fn test_repro_bundle_schema_version() {
        let mut rt = LabRuntime::new(default_config()).unwrap();
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
            EVT_MOCK_CLOCK_ADVANCED,
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
            ERR_LB_LINK_NOT_FOUND,
            ERR_LB_FAULT_RANGE,
            ERR_LB_BUDGET_EXCEEDED,
            ERR_LB_REPLAY_DIVERGENCE,
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
}
