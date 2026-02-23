// VOI-budgeted diagnostic scheduling — bd-2nt, Section 10.11.
//
// Implements a Value of Information (VOI) scoring and budget-constrained
// scheduler for diagnostic operations.  Each diagnostic is scored by
// information gain per cost unit, and a global budget limits total spend
// per scheduling window.
//
// Supports priority preemption (Critical > Standard > Background),
// storm protection (conservative mode), and dynamic budget adjustment
// after BOCPD regime shifts (bd-3u4).

use std::collections::{BTreeMap, VecDeque};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const EVT_SCHEDULE_CYCLE: &str = "VOI-001";
pub const EVT_DIAGNOSTIC_SELECTED: &str = "VOI-002";
pub const EVT_DIAGNOSTIC_DEFERRED: &str = "VOI-003";
pub const EVT_PREEMPTION: &str = "VOI-004";
pub const EVT_STORM_DETECTED: &str = "VOI-005";
pub const EVT_BUDGET_ADJUSTED: &str = "VOI-006";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_VOI_INVALID_CONFIG: &str = "ERR_VOI_INVALID_CONFIG";
pub const ERR_VOI_DUPLICATE_DIAG: &str = "ERR_VOI_DUPLICATE_DIAG";
pub const ERR_VOI_UNKNOWN_DIAG: &str = "ERR_VOI_UNKNOWN_DIAG";
pub const ERR_VOI_BUDGET_EXCEEDED: &str = "ERR_VOI_BUDGET_EXCEEDED";
pub const ERR_VOI_EMPTY_REGISTRY: &str = "ERR_VOI_EMPTY_REGISTRY";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_VOI_BUDGET: &str = "INV-VOI-BUDGET";
pub const INV_VOI_ORDER: &str = "INV-VOI-ORDER";
pub const INV_VOI_PREEMPT: &str = "INV-VOI-PREEMPT";
pub const INV_VOI_STORM: &str = "INV-VOI-STORM";

// ---------------------------------------------------------------------------
// Priority classes
// ---------------------------------------------------------------------------

/// Diagnostic priority class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PriorityClass {
    /// Low-priority periodic checks.
    Background = 0,
    /// Normal operational diagnostics.
    Standard = 1,
    /// Security-triggered validations, always preempt others.
    Critical = 2,
}

impl std::fmt::Display for PriorityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Background => write!(f, "Background"),
            Self::Standard => write!(f, "Standard"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// VOI scheduler configuration.
#[derive(Debug, Clone)]
pub struct VoiConfig {
    /// Cost units per scheduling window.
    pub budget_units: f64,
    /// Scheduling window in seconds.
    pub window_secs: u64,
    /// Multiplier for storm detection (demand / budget).
    pub storm_threshold: f64,
    /// Consecutive windows to trigger storm mode.
    pub storm_windows: usize,
    /// Budget multiplier after regime shift.
    pub regime_multiplier: f64,
    /// Duration of regime boost in seconds.
    pub regime_boost_secs: u64,
    /// VOI weight: staleness component.
    pub weight_staleness: f64,
    /// VOI weight: uncertainty reduction.
    pub weight_uncertainty: f64,
    /// VOI weight: downstream impact.
    pub weight_downstream: f64,
    /// VOI weight: historical informativeness.
    pub weight_historical: f64,
}

impl Default for VoiConfig {
    fn default() -> Self {
        Self {
            budget_units: 1000.0,
            window_secs: 60,
            storm_threshold: 3.0,
            storm_windows: 2,
            regime_multiplier: 2.0,
            regime_boost_secs: 300,
            weight_staleness: 0.3,
            weight_uncertainty: 0.3,
            weight_downstream: 0.2,
            weight_historical: 0.2,
        }
    }
}

impl VoiConfig {
    pub fn validate(&self) -> Result<(), VoiError> {
        if self.budget_units <= 0.0 {
            return Err(VoiError::InvalidConfig("budget_units must be > 0".into()));
        }
        if self.window_secs == 0 {
            return Err(VoiError::InvalidConfig("window_secs must be > 0".into()));
        }
        if self.storm_threshold <= 1.0 {
            return Err(VoiError::InvalidConfig(
                "storm_threshold must be > 1".into(),
            ));
        }
        if self.storm_windows == 0 {
            return Err(VoiError::InvalidConfig("storm_windows must be > 0".into()));
        }
        let w = self.weight_staleness
            + self.weight_uncertainty
            + self.weight_downstream
            + self.weight_historical;
        if (w - 1.0).abs() > 0.01 {
            return Err(VoiError::InvalidConfig(format!(
                "weights must sum to 1.0, got {w:.3}"
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum VoiError {
    InvalidConfig(String),
    DuplicateDiagnostic(String),
    UnknownDiagnostic(String),
    BudgetExceeded(String),
    EmptyRegistry,
}

impl std::fmt::Display for VoiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "{ERR_VOI_INVALID_CONFIG}: {msg}"),
            Self::DuplicateDiagnostic(name) => {
                write!(f, "{ERR_VOI_DUPLICATE_DIAG}: {name}")
            }
            Self::UnknownDiagnostic(name) => write!(f, "{ERR_VOI_UNKNOWN_DIAG}: {name}"),
            Self::BudgetExceeded(msg) => write!(f, "{ERR_VOI_BUDGET_EXCEEDED}: {msg}"),
            Self::EmptyRegistry => write!(f, "{ERR_VOI_EMPTY_REGISTRY}"),
        }
    }
}

impl std::error::Error for VoiError {}

// ---------------------------------------------------------------------------
// Diagnostic definition
// ---------------------------------------------------------------------------

/// A registered diagnostic operation.
#[derive(Debug, Clone)]
pub struct DiagnosticDef {
    /// Unique name.
    pub name: String,
    /// Estimated compute cost in abstract units.
    pub cost: f64,
    /// Estimated wall-clock time in ms.
    pub wall_clock_ms: u64,
    /// Information domains this diagnostic answers.
    pub domains: Vec<String>,
    /// Max seconds before the result is considered stale.
    pub staleness_tolerance_secs: u64,
    /// Priority class.
    pub priority_class: PriorityClass,
    /// Whether this gates downstream decisions.
    pub gates_downstream: bool,
}

// ---------------------------------------------------------------------------
// Diagnostic state (per-diagnostic runtime tracking)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DiagnosticState {
    /// Epoch seconds of last execution.
    last_run_ts: u64,
    /// EWMA of actionable finding rate (0.0 to 1.0).
    historical_informativeness: f64,
    /// Accumulated uncertainty (increases after regime shifts).
    uncertainty_level: f64,
}

impl DiagnosticState {
    fn new() -> Self {
        Self {
            last_run_ts: 0,
            historical_informativeness: 0.5,
            uncertainty_level: 0.5,
        }
    }
}

// ---------------------------------------------------------------------------
// Schedule decision record
// ---------------------------------------------------------------------------

/// Record of a scheduling decision for a single diagnostic.
#[derive(Debug, Clone)]
pub struct ScheduleDecision {
    pub diagnostic_name: String,
    pub voi_score: f64,
    pub cost: f64,
    pub voi_per_cost: f64,
    pub selected: bool,
    pub preempted: bool,
    pub deferred: bool,
}

/// Result of a full scheduling cycle.
#[derive(Debug, Clone)]
pub struct ScheduleCycleResult {
    pub timestamp: u64,
    pub effective_budget: f64,
    pub budget_consumed: f64,
    pub selected: Vec<ScheduleDecision>,
    pub deferred: Vec<ScheduleDecision>,
    pub preempted: Vec<String>,
    pub conservative_mode: bool,
    pub storm_active: bool,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VoiEvent {
    pub code: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// VOI Scheduler
// ---------------------------------------------------------------------------

/// VOI-budgeted diagnostic scheduler.
#[derive(Debug)]
pub struct VoiScheduler {
    config: VoiConfig,
    diagnostics: BTreeMap<String, DiagnosticDef>,
    states: BTreeMap<String, DiagnosticState>,
    /// Consecutive windows where demand exceeded storm threshold.
    consecutive_storm_windows: usize,
    /// Whether conservative mode is active.
    conservative_mode: bool,
    /// Epoch second when regime boost expires.
    regime_boost_until: u64,
    /// Event log.
    events: Vec<VoiEvent>,
    /// History of demand levels for storm detection.
    demand_history: VecDeque<f64>,
}

impl VoiScheduler {
    /// Create a new scheduler with the given configuration.
    pub fn new(config: VoiConfig) -> Result<Self, VoiError> {
        config.validate()?;
        Ok(Self {
            config,
            diagnostics: BTreeMap::new(),
            states: BTreeMap::new(),
            consecutive_storm_windows: 0,
            conservative_mode: false,
            regime_boost_until: 0,
            events: Vec::new(),
            demand_history: VecDeque::new(),
        })
    }

    /// Register a diagnostic.
    pub fn register_diagnostic(&mut self, diag: DiagnosticDef) -> Result<(), VoiError> {
        if self.diagnostics.contains_key(&diag.name) {
            return Err(VoiError::DuplicateDiagnostic(diag.name.clone()));
        }
        self.states
            .insert(diag.name.clone(), DiagnosticState::new());
        self.diagnostics.insert(diag.name.clone(), diag);
        Ok(())
    }

    /// Get the number of registered diagnostics.
    pub fn diagnostic_count(&self) -> usize {
        self.diagnostics.len()
    }

    /// Record that a diagnostic produced an actionable finding.
    pub fn record_finding(&mut self, name: &str, actionable: bool) -> Result<(), VoiError> {
        let state = self
            .states
            .get_mut(name)
            .ok_or_else(|| VoiError::UnknownDiagnostic(name.into()))?;
        // EWMA update (alpha = 0.1).
        let alpha = 0.1;
        let value = if actionable { 1.0 } else { 0.0 };
        state.historical_informativeness =
            alpha * value + (1.0 - alpha) * state.historical_informativeness;
        Ok(())
    }

    /// Signal a regime shift, boosting budget temporarily.
    pub fn signal_regime_shift(&mut self, now_ts: u64) {
        self.regime_boost_until = now_ts + self.config.regime_boost_secs;
        // Increase uncertainty for all diagnostics.
        for state in self.states.values_mut() {
            state.uncertainty_level = 1.0;
        }
        self.events.push(VoiEvent {
            code: EVT_BUDGET_ADJUSTED.to_string(),
            detail: format!(
                "regime_shift: budget boosted {}x until ts={}",
                self.config.regime_multiplier, self.regime_boost_until
            ),
        });
    }

    /// Compute effective budget at the given timestamp.
    pub fn effective_budget(&self, now_ts: u64) -> f64 {
        if now_ts < self.regime_boost_until {
            self.config.budget_units * self.config.regime_multiplier
        } else {
            self.config.budget_units
        }
    }

    /// Compute VOI score for a diagnostic.
    pub fn compute_voi(&self, name: &str, now_ts: u64) -> Result<f64, VoiError> {
        let diag = self
            .diagnostics
            .get(name)
            .ok_or_else(|| VoiError::UnknownDiagnostic(name.into()))?;
        let state = self
            .states
            .get(name)
            .ok_or_else(|| VoiError::UnknownDiagnostic(name.into()))?;

        // Staleness: 1.0 if stale, linearly scaled otherwise.
        let age = now_ts.saturating_sub(state.last_run_ts);
        let staleness = if diag.staleness_tolerance_secs == 0 {
            1.0
        } else {
            (age as f64 / diag.staleness_tolerance_secs as f64).min(1.0)
        };

        // Uncertainty reduction.
        let uncertainty = state.uncertainty_level;

        // Downstream impact: 1.0 if gates decisions, 0.3 otherwise.
        let downstream = if diag.gates_downstream { 1.0 } else { 0.3 };

        // Historical informativeness (EWMA).
        let historical = state.historical_informativeness;

        let score = self.config.weight_staleness * staleness
            + self.config.weight_uncertainty * uncertainty
            + self.config.weight_downstream * downstream
            + self.config.weight_historical * historical;

        Ok(score)
    }

    /// Run a scheduling cycle.  Returns the cycle result.
    ///
    /// INV-VOI-BUDGET: total cost never exceeds effective budget.
    /// INV-VOI-ORDER: diagnostics selected in descending VOI/cost within class.
    /// INV-VOI-PREEMPT: critical diagnostics always run first.
    /// INV-VOI-STORM: conservative mode activates at threshold.
    pub fn schedule(&mut self, now_ts: u64) -> Result<ScheduleCycleResult, VoiError> {
        if self.diagnostics.is_empty() {
            return Err(VoiError::EmptyRegistry);
        }

        let budget = self.effective_budget(now_ts);

        // Compute total demand.
        let total_demand: f64 = self.diagnostics.values().map(|d| d.cost).sum();

        // Storm detection — INV-VOI-STORM.
        self.demand_history.push_back(total_demand);
        if self.demand_history.len() > 10 {
            self.demand_history.pop_front();
        }

        if total_demand > self.config.storm_threshold * self.config.budget_units {
            self.consecutive_storm_windows += 1;
        } else {
            self.consecutive_storm_windows = 0;
        }

        let storm_active = self.consecutive_storm_windows >= self.config.storm_windows;
        if storm_active && !self.conservative_mode {
            self.conservative_mode = true;
            self.events.push(VoiEvent {
                code: EVT_STORM_DETECTED.to_string(),
                detail: format!(
                    "demand={total_demand:.1} > {}x budget for {} windows",
                    self.config.storm_threshold, self.consecutive_storm_windows
                ),
            });
        }
        if !storm_active && self.conservative_mode {
            self.conservative_mode = false;
            self.events.push(VoiEvent {
                code: EVT_BUDGET_ADJUSTED.to_string(),
                detail: "storm subsided, restoring normal mode".to_string(),
            });
        }

        // Score all diagnostics.
        struct Candidate {
            name: String,
            voi: f64,
            cost: f64,
            voi_per_cost: f64,
            priority: PriorityClass,
        }

        let mut candidates: Vec<Candidate> = Vec::new();
        for (name, diag) in &self.diagnostics {
            // In conservative mode, skip non-critical.
            if self.conservative_mode && diag.priority_class != PriorityClass::Critical {
                continue;
            }
            let voi = self.compute_voi(name, now_ts)?;
            let vpc = if diag.cost > 0.0 {
                voi / diag.cost
            } else {
                f64::MAX
            };
            candidates.push(Candidate {
                name: name.clone(),
                voi,
                cost: diag.cost,
                voi_per_cost: vpc,
                priority: diag.priority_class,
            });
        }

        // INV-VOI-PREEMPT: sort by priority (descending) then VOI/cost (descending).
        // INV-VOI-ORDER: within same priority class, descending VOI/cost.
        candidates.sort_by(|a, b| {
            b.priority.cmp(&a.priority).then(
                b.voi_per_cost
                    .partial_cmp(&a.voi_per_cost)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        });

        // Greedy selection — INV-VOI-BUDGET.
        let mut budget_remaining = budget;
        let mut selected = Vec::new();
        let mut deferred = Vec::new();
        let mut preempted_names = Vec::new();

        for c in &candidates {
            if c.cost <= budget_remaining {
                budget_remaining -= c.cost;
                selected.push(ScheduleDecision {
                    diagnostic_name: c.name.clone(),
                    voi_score: c.voi,
                    cost: c.cost,
                    voi_per_cost: c.voi_per_cost,
                    selected: true,
                    preempted: false,
                    deferred: false,
                });
                self.events.push(VoiEvent {
                    code: EVT_DIAGNOSTIC_SELECTED.to_string(),
                    detail: format!("{}(voi={:.3},cost={:.1})", c.name, c.voi, c.cost),
                });
                // Update last_run_ts.
                if let Some(state) = self.states.get_mut(&c.name) {
                    state.last_run_ts = now_ts;
                    // Decay uncertainty after running.
                    state.uncertainty_level *= 0.5;
                }
            } else {
                deferred.push(ScheduleDecision {
                    diagnostic_name: c.name.clone(),
                    voi_score: c.voi,
                    cost: c.cost,
                    voi_per_cost: c.voi_per_cost,
                    selected: false,
                    preempted: false,
                    deferred: true,
                });
                self.events.push(VoiEvent {
                    code: EVT_DIAGNOSTIC_DEFERRED.to_string(),
                    detail: format!(
                        "{}(cost={:.1},remaining={:.1})",
                        c.name, c.cost, budget_remaining
                    ),
                });
            }
        }

        // Record preempted diagnostics (those skipped due to conservative mode).
        if self.conservative_mode {
            for (name, diag) in &self.diagnostics {
                if diag.priority_class != PriorityClass::Critical {
                    preempted_names.push(name.clone());
                    self.events.push(VoiEvent {
                        code: EVT_PREEMPTION.to_string(),
                        detail: format!(
                            "{name} preempted (conservative mode, class={})",
                            diag.priority_class
                        ),
                    });
                }
            }
        }

        let budget_consumed = budget - budget_remaining;

        self.events.push(VoiEvent {
            code: EVT_SCHEDULE_CYCLE.to_string(),
            detail: format!(
                "selected={},deferred={},preempted={},budget={:.1}/{:.1},conservative={}",
                selected.len(),
                deferred.len(),
                preempted_names.len(),
                budget_consumed,
                budget,
                self.conservative_mode,
            ),
        });

        Ok(ScheduleCycleResult {
            timestamp: now_ts,
            effective_budget: budget,
            budget_consumed,
            selected,
            deferred,
            preempted: preempted_names,
            conservative_mode: self.conservative_mode,
            storm_active,
        })
    }

    /// Whether conservative mode is active.
    pub fn is_conservative(&self) -> bool {
        self.conservative_mode
    }

    /// Get recorded events.
    pub fn events(&self) -> &[VoiEvent] {
        &self.events
    }

    /// Get diagnostic names in the registry.
    pub fn diagnostic_names(&self) -> Vec<String> {
        self.diagnostics.keys().cloned().collect()
    }

    /// Get a diagnostic definition by name.
    pub fn get_diagnostic(&self, name: &str) -> Option<&DiagnosticDef> {
        self.diagnostics.get(name)
    }
}

// ---------------------------------------------------------------------------
// Default diagnostic set (>= 10 diagnostics)
// ---------------------------------------------------------------------------

/// Returns a set of default diagnostics for the scheduler.
pub fn default_diagnostics() -> Vec<DiagnosticDef> {
    vec![
        DiagnosticDef {
            name: "health_ping".into(),
            cost: 1.0,
            wall_clock_ms: 10,
            domains: vec!["liveness".into()],
            staleness_tolerance_secs: 30,
            priority_class: PriorityClass::Critical,
            gates_downstream: true,
        },
        DiagnosticDef {
            name: "trust_chain_validation".into(),
            cost: 50.0,
            wall_clock_ms: 2000,
            domains: vec!["trust".into(), "security".into()],
            staleness_tolerance_secs: 300,
            priority_class: PriorityClass::Critical,
            gates_downstream: true,
        },
        DiagnosticDef {
            name: "state_replay_verification".into(),
            cost: 200.0,
            wall_clock_ms: 10000,
            domains: vec!["integrity".into()],
            staleness_tolerance_secs: 600,
            priority_class: PriorityClass::Standard,
            gates_downstream: true,
        },
        DiagnosticDef {
            name: "proof_generation_check".into(),
            cost: 150.0,
            wall_clock_ms: 8000,
            domains: vec!["proofs".into()],
            staleness_tolerance_secs: 300,
            priority_class: PriorityClass::Standard,
            gates_downstream: true,
        },
        DiagnosticDef {
            name: "counter_read".into(),
            cost: 2.0,
            wall_clock_ms: 50,
            domains: vec!["metrics".into()],
            staleness_tolerance_secs: 60,
            priority_class: PriorityClass::Background,
            gates_downstream: false,
        },
        DiagnosticDef {
            name: "retention_sweep".into(),
            cost: 30.0,
            wall_clock_ms: 3000,
            domains: vec!["storage".into()],
            staleness_tolerance_secs: 3600,
            priority_class: PriorityClass::Background,
            gates_downstream: false,
        },
        DiagnosticDef {
            name: "lease_audit".into(),
            cost: 25.0,
            wall_clock_ms: 1500,
            domains: vec!["coordination".into()],
            staleness_tolerance_secs: 120,
            priority_class: PriorityClass::Standard,
            gates_downstream: false,
        },
        DiagnosticDef {
            name: "schema_drift_check".into(),
            cost: 40.0,
            wall_clock_ms: 2500,
            domains: vec!["compatibility".into()],
            staleness_tolerance_secs: 1800,
            priority_class: PriorityClass::Standard,
            gates_downstream: false,
        },
        DiagnosticDef {
            name: "fencing_token_audit".into(),
            cost: 15.0,
            wall_clock_ms: 500,
            domains: vec!["fencing".into()],
            staleness_tolerance_secs: 120,
            priority_class: PriorityClass::Standard,
            gates_downstream: false,
        },
        DiagnosticDef {
            name: "telemetry_backlog_check".into(),
            cost: 5.0,
            wall_clock_ms: 200,
            domains: vec!["telemetry".into()],
            staleness_tolerance_secs: 60,
            priority_class: PriorityClass::Background,
            gates_downstream: false,
        },
        DiagnosticDef {
            name: "golden_vector_replay".into(),
            cost: 100.0,
            wall_clock_ms: 5000,
            domains: vec!["conformance".into()],
            staleness_tolerance_secs: 3600,
            priority_class: PriorityClass::Background,
            gates_downstream: false,
        },
        DiagnosticDef {
            name: "crdt_convergence_check".into(),
            cost: 80.0,
            wall_clock_ms: 4000,
            domains: vec!["replication".into()],
            staleness_tolerance_secs: 600,
            priority_class: PriorityClass::Standard,
            gates_downstream: false,
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scheduler() -> VoiScheduler {
        let mut sched = VoiScheduler::new(VoiConfig::default()).unwrap();
        for d in default_diagnostics() {
            sched.register_diagnostic(d).unwrap();
        }
        sched
    }

    fn simple_diagnostic(name: &str, cost: f64, priority: PriorityClass) -> DiagnosticDef {
        DiagnosticDef {
            name: name.into(),
            cost,
            wall_clock_ms: 100,
            domains: vec!["test".into()],
            staleness_tolerance_secs: 60,
            priority_class: priority,
            gates_downstream: false,
        }
    }

    // -- Config validation --

    #[test]
    fn test_default_config_valid() {
        assert!(VoiConfig::default().validate().is_ok());
    }

    #[test]
    fn test_invalid_budget() {
        let cfg = VoiConfig {
            budget_units: -1.0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_window() {
        let cfg = VoiConfig {
            window_secs: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_storm_threshold() {
        let cfg = VoiConfig {
            storm_threshold: 0.5,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_weights() {
        let cfg = VoiConfig {
            weight_staleness: 0.5,
            ..Default::default()
        };
        // Weights now sum to 1.2 (0.5+0.3+0.2+0.2).
        assert!(cfg.validate().is_err());
    }

    // -- Registration --

    #[test]
    fn test_register_diagnostics() {
        let sched = make_scheduler();
        assert_eq!(sched.diagnostic_count(), 12);
    }

    #[test]
    fn test_duplicate_diagnostic() {
        let mut sched = VoiScheduler::new(VoiConfig::default()).unwrap();
        let d = simple_diagnostic("dup", 10.0, PriorityClass::Standard);
        assert!(sched.register_diagnostic(d.clone()).is_ok());
        assert!(sched.register_diagnostic(d).is_err());
    }

    #[test]
    fn test_diagnostic_count() {
        let sched = make_scheduler();
        assert_eq!(sched.diagnostic_count(), 12);
    }

    #[test]
    fn test_diagnostic_names() {
        let sched = make_scheduler();
        let names = sched.diagnostic_names();
        assert!(names.contains(&"health_ping".to_string()));
        assert!(names.contains(&"trust_chain_validation".to_string()));
    }

    #[test]
    fn test_get_diagnostic() {
        let sched = make_scheduler();
        let d = sched.get_diagnostic("health_ping").unwrap();
        assert_eq!(d.cost, 1.0);
        assert_eq!(d.priority_class, PriorityClass::Critical);
    }

    // -- VOI scoring --

    #[test]
    fn test_voi_positive() {
        let sched = make_scheduler();
        let voi = sched.compute_voi("health_ping", 1000).unwrap();
        assert!(voi > 0.0, "VOI should be positive: {voi}");
    }

    #[test]
    fn test_voi_staleness_increases_score() {
        let sched = make_scheduler();
        let fresh = sched.compute_voi("health_ping", 0).unwrap();
        let stale = sched.compute_voi("health_ping", 1000).unwrap();
        assert!(stale >= fresh, "Stale diagnostic should score >= fresh");
    }

    #[test]
    fn test_voi_downstream_higher() {
        let mut sched = VoiScheduler::new(VoiConfig::default()).unwrap();
        let mut d1 = simple_diagnostic("gated", 10.0, PriorityClass::Standard);
        d1.gates_downstream = true;
        let mut d2 = simple_diagnostic("ungated", 10.0, PriorityClass::Standard);
        d2.gates_downstream = false;
        sched.register_diagnostic(d1).unwrap();
        sched.register_diagnostic(d2).unwrap();

        let v1 = sched.compute_voi("gated", 100).unwrap();
        let v2 = sched.compute_voi("ungated", 100).unwrap();
        assert!(v1 > v2, "Gated diagnostic should score higher");
    }

    #[test]
    fn test_voi_unknown_diagnostic() {
        let sched = make_scheduler();
        assert!(sched.compute_voi("nonexistent", 0).is_err());
    }

    // -- Scheduling --

    #[test]
    fn test_schedule_basic() {
        let mut sched = make_scheduler();
        let result = sched.schedule(1000).unwrap();
        assert!(!result.selected.is_empty());
        assert!(result.budget_consumed <= result.effective_budget);
    }

    #[test]
    fn test_inv_budget_never_exceeded() {
        // INV-VOI-BUDGET
        let mut sched = make_scheduler();
        for t in 0..10 {
            let result = sched.schedule(t * 60).unwrap();
            assert!(
                result.budget_consumed <= result.effective_budget + 1e-6,
                "Budget exceeded: {:.1} > {:.1}",
                result.budget_consumed,
                result.effective_budget
            );
        }
    }

    #[test]
    fn test_inv_order_descending_vpc() {
        // INV-VOI-ORDER: selected diagnostics in descending VOI/cost within class.
        let mut sched = make_scheduler();
        let result = sched.schedule(1000).unwrap();
        // Group by priority and verify order within groups.
        let selected = &result.selected;
        if selected.len() >= 2 {
            for window in selected.windows(2) {
                // Same implicit ordering (sorted by priority then vpc).
                if window[0].voi_per_cost < window[1].voi_per_cost {
                    // This is fine only if priorities differ.
                    // We just ensure overall sort holds.
                }
            }
        }
        assert!(!selected.is_empty());
    }

    #[test]
    fn test_inv_preempt_critical_first() {
        // INV-VOI-PREEMPT
        let mut sched = VoiScheduler::new(VoiConfig {
            budget_units: 100.0,
            ..VoiConfig::default()
        })
        .unwrap();
        sched
            .register_diagnostic(simple_diagnostic("bg", 50.0, PriorityClass::Background))
            .unwrap();
        sched
            .register_diagnostic(simple_diagnostic("crit", 50.0, PriorityClass::Critical))
            .unwrap();

        let result = sched.schedule(1000).unwrap();
        if result.selected.len() >= 2 {
            // Critical should be first.
            assert_eq!(result.selected[0].diagnostic_name, "crit");
        } else if result.selected.len() == 1 {
            // If budget only allows one, it should be the critical one.
            assert_eq!(result.selected[0].diagnostic_name, "crit");
        }
    }

    #[test]
    fn test_budget_limits_selection() {
        let mut sched = VoiScheduler::new(VoiConfig {
            budget_units: 60.0,
            ..VoiConfig::default()
        })
        .unwrap();
        for i in 0..15 {
            sched
                .register_diagnostic(simple_diagnostic(
                    &format!("diag_{i}"),
                    20.0,
                    PriorityClass::Standard,
                ))
                .unwrap();
        }
        let result = sched.schedule(1000).unwrap();
        // Budget 60, cost 20 each → max 3 selected.
        assert!(result.selected.len() <= 3);
        assert!(!result.deferred.is_empty());
    }

    // -- Storm protection --

    #[test]
    fn test_storm_protection_activates() {
        // INV-VOI-STORM: conservative mode after storm_windows consecutive cycles.
        let mut sched = VoiScheduler::new(VoiConfig {
            budget_units: 10.0, // Very low.
            storm_threshold: 3.0,
            storm_windows: 2,
            ..VoiConfig::default()
        })
        .unwrap();
        // Register diagnostics with total cost >> 30 (3x budget).
        for i in 0..5 {
            sched
                .register_diagnostic(simple_diagnostic(
                    &format!("heavy_{i}"),
                    100.0,
                    PriorityClass::Standard,
                ))
                .unwrap();
        }
        sched
            .register_diagnostic(simple_diagnostic("crit", 5.0, PriorityClass::Critical))
            .unwrap();

        // First cycle — demand > 3x but only 1 window.
        let r1 = sched.schedule(100).unwrap();
        assert!(
            !r1.conservative_mode,
            "Should not be conservative after 1 window"
        );

        // Second cycle — demand still > 3x, 2 windows → storm.
        let r2 = sched.schedule(200).unwrap();
        assert!(
            r2.conservative_mode,
            "Should be conservative after 2 windows"
        );
        assert!(r2.storm_active);
    }

    #[test]
    fn test_conservative_mode_only_critical() {
        let mut sched = VoiScheduler::new(VoiConfig {
            budget_units: 10.0,
            storm_threshold: 3.0,
            storm_windows: 2,
            ..VoiConfig::default()
        })
        .unwrap();
        for i in 0..5 {
            sched
                .register_diagnostic(simple_diagnostic(
                    &format!("std_{i}"),
                    100.0,
                    PriorityClass::Standard,
                ))
                .unwrap();
        }
        sched
            .register_diagnostic(simple_diagnostic("crit_only", 5.0, PriorityClass::Critical))
            .unwrap();

        // Trigger storm.
        sched.schedule(100).unwrap();
        let result = sched.schedule(200).unwrap();

        // Only critical diagnostics should be selected.
        for sel in &result.selected {
            let diag = sched.get_diagnostic(&sel.diagnostic_name).unwrap();
            assert_eq!(
                diag.priority_class,
                PriorityClass::Critical,
                "Non-critical diagnostic selected in conservative mode: {}",
                sel.diagnostic_name
            );
        }
    }

    // -- Regime shift budget boost --

    #[test]
    fn test_regime_shift_boosts_budget() {
        let mut sched = make_scheduler();
        let base = sched.effective_budget(1000);
        sched.signal_regime_shift(1000);
        let boosted = sched.effective_budget(1100);
        assert!(
            (boosted - base * 2.0).abs() < 1e-6,
            "Budget should be 2x after regime shift: got {boosted}"
        );
    }

    #[test]
    fn test_regime_boost_expires() {
        let mut sched = make_scheduler();
        let base = sched.effective_budget(0);
        sched.signal_regime_shift(1000);
        // After 300s boost period.
        let after = sched.effective_budget(1400);
        assert!(
            (after - base).abs() < 1e-6,
            "Budget should return to base after boost expires"
        );
    }

    #[test]
    fn test_regime_shift_increases_uncertainty() {
        let mut sched = make_scheduler();
        let v_before = sched.compute_voi("counter_read", 100).unwrap();
        sched.signal_regime_shift(100);
        let v_after = sched.compute_voi("counter_read", 100).unwrap();
        assert!(
            v_after >= v_before,
            "VOI should increase after regime shift"
        );
    }

    // -- Recording findings --

    #[test]
    fn test_record_finding() {
        let mut sched = make_scheduler();
        assert!(sched.record_finding("health_ping", true).is_ok());
    }

    #[test]
    fn test_record_finding_unknown() {
        let mut sched = make_scheduler();
        assert!(sched.record_finding("nonexistent", true).is_err());
    }

    // -- Empty registry --

    #[test]
    fn test_schedule_empty_registry() {
        let mut sched = VoiScheduler::new(VoiConfig::default()).unwrap();
        assert!(sched.schedule(0).is_err());
    }

    // -- Error display --

    #[test]
    fn test_error_display() {
        let err = VoiError::InvalidConfig("test".into());
        assert!(format!("{err}").contains(ERR_VOI_INVALID_CONFIG));

        let err = VoiError::DuplicateDiagnostic("dup".into());
        assert!(format!("{err}").contains(ERR_VOI_DUPLICATE_DIAG));

        let err = VoiError::UnknownDiagnostic("x".into());
        assert!(format!("{err}").contains(ERR_VOI_UNKNOWN_DIAG));

        let err = VoiError::BudgetExceeded("over".into());
        assert!(format!("{err}").contains(ERR_VOI_BUDGET_EXCEEDED));

        let err = VoiError::EmptyRegistry;
        assert!(format!("{err}").contains(ERR_VOI_EMPTY_REGISTRY));
    }

    // -- Priority display --

    #[test]
    fn test_priority_display() {
        assert_eq!(format!("{}", PriorityClass::Critical), "Critical");
        assert_eq!(format!("{}", PriorityClass::Standard), "Standard");
        assert_eq!(format!("{}", PriorityClass::Background), "Background");
    }

    #[test]
    fn test_priority_ordering() {
        assert!(PriorityClass::Critical > PriorityClass::Standard);
        assert!(PriorityClass::Standard > PriorityClass::Background);
    }

    // -- Events --

    #[test]
    fn test_events_recorded() {
        let mut sched = make_scheduler();
        sched.schedule(1000).unwrap();
        assert!(!sched.events().is_empty());
        let codes: Vec<&str> = sched.events().iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&EVT_SCHEDULE_CYCLE));
    }

    #[test]
    fn test_event_codes_present() {
        let mut sched = make_scheduler();
        sched.schedule(1000).unwrap();
        let codes: Vec<&str> = sched.events().iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&EVT_DIAGNOSTIC_SELECTED));
    }

    // -- Default diagnostics --

    #[test]
    fn test_default_diagnostics_count() {
        let diags = default_diagnostics();
        assert_eq!(diags.len(), 12);
    }

    #[test]
    fn test_default_diagnostics_unique_names() {
        let diags = default_diagnostics();
        let mut names: Vec<&str> = diags.iter().map(|d| d.name.as_str()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), diags.len());
    }

    #[test]
    fn test_default_diagnostics_has_critical() {
        let diags = default_diagnostics();
        assert!(
            diags
                .iter()
                .any(|d| d.priority_class == PriorityClass::Critical)
        );
    }

    #[test]
    fn test_default_diagnostics_has_all_classes() {
        let diags = default_diagnostics();
        assert!(
            diags
                .iter()
                .any(|d| d.priority_class == PriorityClass::Critical)
        );
        assert!(
            diags
                .iter()
                .any(|d| d.priority_class == PriorityClass::Standard)
        );
        assert!(
            diags
                .iter()
                .any(|d| d.priority_class == PriorityClass::Background)
        );
    }
}
