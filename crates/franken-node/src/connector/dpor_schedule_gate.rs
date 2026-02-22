//! bd-25oa: DPOR schedule gate for control-plane interaction scenarios.
//!
//! Wraps the canonical DPOR exploration framework from bd-22yy
//! (`control_plane::dpor_exploration`) and registers six interaction
//! scenarios that cover epoch, lease, remote, and evidence protocols:
//!
//! 1. `epoch_lease_interleave` — epoch transitions racing with lease renewals
//! 2. `remote_evidence_race` — remote computation vs evidence emission
//! 3. `lease_remote_conflict` — lease acquisition conflicting with remote ops
//! 4. `evidence_epoch_barrier` — evidence emission blocked by epoch barriers
//! 5. `epoch_remote_fence` — epoch fencing token vs remote capability
//! 6. `lease_evidence_sync` — lease lifecycle synchronized with evidence log
//!
//! # Invariants
//!
//! - INV-DSG-CANONICAL: all exploration uses the canonical DporExplorer
//! - INV-DSG-BOUNDED: exploration respects time/memory budgets per scenario
//! - INV-DSG-COVERAGE: all six scenarios are explored and coverage tracked
//! - INV-DSG-COUNTEREXAMPLE: violations produce minimal counterexample traces
//! - INV-DSG-DETERMINISTIC: same scenarios always produce same exploration order
//! - INV-DSG-SAFETY: safety properties checked at every explored state

use crate::control_plane::dpor_exploration::{
    CounterexampleStep, DporExplorer, ExplorationBudget, ExplorationResult, Operation,
    ProtocolModel, ProtocolModelId, SafetyProperty,
};

/// Type alias for a list of scenario names paired with their model-builder functions.
type ScenarioBuilderList<'a> = Vec<(&'a str, fn() -> ProtocolModel)>;

/// Type alias for the result of a safety-violation check: `None` means safe,
/// `Some((description, trace))` describes the violation.
type SafetyViolation = Option<(String, Vec<CounterexampleStep>)>;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for DPOR schedule gate reports.
pub const SCHEMA_VERSION: &str = "dsg-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const DSG_001: &str = "DSG-001";
    pub const DSG_002: &str = "DSG-002";
    pub const DSG_003: &str = "DSG-003";
    pub const DSG_004: &str = "DSG-004";
    pub const DSG_005: &str = "DSG-005";
    pub const DSG_006: &str = "DSG-006";
    pub const DSG_007: &str = "DSG-007";
    pub const DSG_008: &str = "DSG-008";
}

/// Human-readable descriptions for event codes.
pub fn event_description(code: &str) -> &'static str {
    match code {
        event_codes::DSG_001 => "schedule gate initialized",
        event_codes::DSG_002 => "scenario registered",
        event_codes::DSG_003 => "exploration started for scenario",
        event_codes::DSG_004 => "exploration completed for scenario",
        event_codes::DSG_005 => "violation found — counterexample emitted",
        event_codes::DSG_006 => "full gate run started",
        event_codes::DSG_007 => "full gate run completed",
        event_codes::DSG_008 => "budget exceeded for scenario",
        _ => "unknown event code",
    }
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_DSG_NO_SCENARIOS: &str = "ERR_DSG_NO_SCENARIOS";
pub const ERR_DSG_REGISTRATION_FAILED: &str = "ERR_DSG_REGISTRATION_FAILED";
pub const ERR_DSG_EXPLORATION_FAILED: &str = "ERR_DSG_EXPLORATION_FAILED";
pub const ERR_DSG_BUDGET_EXCEEDED: &str = "ERR_DSG_BUDGET_EXCEEDED";
pub const ERR_DSG_SCENARIO_NOT_FOUND: &str = "ERR_DSG_SCENARIO_NOT_FOUND";
pub const ERR_DSG_SAFETY_VIOLATION: &str = "ERR_DSG_SAFETY_VIOLATION";
pub const ERR_DSG_INCOMPLETE_COVERAGE: &str = "ERR_DSG_INCOMPLETE_COVERAGE";
pub const ERR_DSG_INVALID_CONFIG: &str = "ERR_DSG_INVALID_CONFIG";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_DSG_CANONICAL: &str = "INV-DSG-CANONICAL";
pub const INV_DSG_BOUNDED: &str = "INV-DSG-BOUNDED";
pub const INV_DSG_COVERAGE: &str = "INV-DSG-COVERAGE";
pub const INV_DSG_COUNTEREXAMPLE: &str = "INV-DSG-COUNTEREXAMPLE";
pub const INV_DSG_DETERMINISTIC: &str = "INV-DSG-DETERMINISTIC";
pub const INV_DSG_SAFETY: &str = "INV-DSG-SAFETY";

// ---------------------------------------------------------------------------
// Scenario names (canonical identifiers)
// ---------------------------------------------------------------------------

pub const SCENARIO_EPOCH_LEASE_INTERLEAVE: &str = "epoch_lease_interleave";
pub const SCENARIO_REMOTE_EVIDENCE_RACE: &str = "remote_evidence_race";
pub const SCENARIO_LEASE_REMOTE_CONFLICT: &str = "lease_remote_conflict";
pub const SCENARIO_EVIDENCE_EPOCH_BARRIER: &str = "evidence_epoch_barrier";
pub const SCENARIO_EPOCH_REMOTE_FENCE: &str = "epoch_remote_fence";
pub const SCENARIO_LEASE_EVIDENCE_SYNC: &str = "lease_evidence_sync";

/// All six canonical scenario names.
pub const ALL_SCENARIOS: &[&str] = &[
    SCENARIO_EPOCH_LEASE_INTERLEAVE,
    SCENARIO_REMOTE_EVIDENCE_RACE,
    SCENARIO_LEASE_REMOTE_CONFLICT,
    SCENARIO_EVIDENCE_EPOCH_BARRIER,
    SCENARIO_EPOCH_REMOTE_FENCE,
    SCENARIO_LEASE_EVIDENCE_SYNC,
];

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the DPOR schedule gate.
#[derive(Debug, Clone)]
pub struct DporScheduleGateConfig {
    /// Time budget per scenario in seconds.
    pub time_budget_per_scenario_secs: u64,
    /// Memory budget per scenario in bytes.
    pub memory_budget_bytes: u64,
}

impl Default for DporScheduleGateConfig {
    fn default() -> Self {
        Self {
            time_budget_per_scenario_secs: 120,
            memory_budget_bytes: 1_073_741_824, // 1 GB
        }
    }
}

impl DporScheduleGateConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), DporScheduleGateError> {
        if self.time_budget_per_scenario_secs == 0 {
            return Err(DporScheduleGateError::InvalidConfig(
                "time_budget_per_scenario_secs must be > 0".into(),
            ));
        }
        if self.memory_budget_bytes == 0 {
            return Err(DporScheduleGateError::InvalidConfig(
                "memory_budget_bytes must be > 0".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the DPOR schedule gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DporScheduleGateError {
    NoScenarios,
    RegistrationFailed(String),
    ExplorationFailed(String),
    BudgetExceeded { scenario: String },
    ScenarioNotFound(String),
    SafetyViolation { scenario: String, property: String },
    IncompleteCoverage { explored: usize, expected: usize },
    InvalidConfig(String),
}

impl DporScheduleGateError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoScenarios => ERR_DSG_NO_SCENARIOS,
            Self::RegistrationFailed(_) => ERR_DSG_REGISTRATION_FAILED,
            Self::ExplorationFailed(_) => ERR_DSG_EXPLORATION_FAILED,
            Self::BudgetExceeded { .. } => ERR_DSG_BUDGET_EXCEEDED,
            Self::ScenarioNotFound(_) => ERR_DSG_SCENARIO_NOT_FOUND,
            Self::SafetyViolation { .. } => ERR_DSG_SAFETY_VIOLATION,
            Self::IncompleteCoverage { .. } => ERR_DSG_INCOMPLETE_COVERAGE,
            Self::InvalidConfig(_) => ERR_DSG_INVALID_CONFIG,
        }
    }
}

impl std::fmt::Display for DporScheduleGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoScenarios => write!(f, "{}: no scenarios registered", self.code()),
            Self::RegistrationFailed(detail) => {
                write!(f, "{}: {}", self.code(), detail)
            }
            Self::ExplorationFailed(detail) => {
                write!(f, "{}: {}", self.code(), detail)
            }
            Self::BudgetExceeded { scenario } => {
                write!(f, "{}: budget exceeded for {}", self.code(), scenario)
            }
            Self::ScenarioNotFound(name) => {
                write!(f, "{}: scenario '{}' not found", self.code(), name)
            }
            Self::SafetyViolation { scenario, property } => {
                write!(
                    f,
                    "{}: scenario '{}' violated property '{}'",
                    self.code(),
                    scenario,
                    property
                )
            }
            Self::IncompleteCoverage { explored, expected } => {
                write!(
                    f,
                    "{}: explored {}/{} scenarios",
                    self.code(),
                    explored,
                    expected
                )
            }
            Self::InvalidConfig(detail) => {
                write!(f, "{}: {}", self.code(), detail)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Gate result
// ---------------------------------------------------------------------------

/// Result of a full gate run across all scenarios.
#[derive(Debug, Clone)]
pub struct GateResult {
    pub schema_version: String,
    pub scenarios_explored: usize,
    pub scenarios_total: usize,
    pub total_schedules_explored: u64,
    pub total_violations: usize,
    pub per_scenario: Vec<ExplorationResult>,
    pub verdict: String,
}

impl GateResult {
    pub fn is_pass(&self) -> bool {
        self.verdict == "PASS"
    }
}

// ---------------------------------------------------------------------------
// Scenario builders
// ---------------------------------------------------------------------------

/// Build the epoch_lease_interleave scenario model.
fn build_epoch_lease_interleave() -> ProtocolModel {
    let mut m = ProtocolModel::new(
        ProtocolModelId::Custom(SCENARIO_EPOCH_LEASE_INTERLEAVE.into()),
        "Epoch transitions racing with lease renewals",
    );
    m.add_operation(Operation::new(
        "epoch-propose",
        "leader",
        "Propose epoch transition",
    ));
    m.add_operation(Operation::new(
        "lease-request",
        "tenant",
        "Request lease renewal",
    ));
    m.add_operation(
        Operation::new("epoch-drain", "leader", "Drain in-flight for epoch")
            .with_dep("epoch-propose"),
    );
    m.add_operation(
        Operation::new("lease-grant", "coordinator", "Grant lease").with_dep("lease-request"),
    );
    m.add_operation(
        Operation::new("epoch-commit", "leader", "Commit epoch advance").with_dep("epoch-drain"),
    );
    m.add_operation(
        Operation::new("lease-activate", "tenant", "Activate renewed lease")
            .with_dep("lease-grant"),
    );

    m.add_safety_property(SafetyProperty::new(
        "no_split_brain",
        "No two epochs are active simultaneously",
    ));
    m.add_safety_property(SafetyProperty::new(
        "no_stale_lease",
        "No lease survives its granting epoch boundary",
    ));
    m.add_safety_property(SafetyProperty::new(
        "no_deadlock",
        "Epoch and lease operations do not deadlock",
    ));
    m
}

/// Build the remote_evidence_race scenario model.
fn build_remote_evidence_race() -> ProtocolModel {
    let mut m = ProtocolModel::new(
        ProtocolModelId::Custom(SCENARIO_REMOTE_EVIDENCE_RACE.into()),
        "Remote computation completion racing with evidence emission",
    );
    m.add_operation(Operation::new(
        "remote-acquire",
        "client",
        "Acquire remote capability",
    ));
    m.add_operation(
        Operation::new("remote-execute", "client", "Execute remote operation")
            .with_dep("remote-acquire"),
    );
    m.add_operation(Operation::new(
        "evidence-begin",
        "verifier",
        "Begin evidence emission",
    ));
    m.add_operation(
        Operation::new("remote-complete", "client", "Complete remote computation")
            .with_dep("remote-execute"),
    );
    m.add_operation(
        Operation::new("evidence-commit", "verifier", "Commit evidence record")
            .with_dep("evidence-begin"),
    );
    m.add_operation(
        Operation::new("remote-release", "client", "Release remote capability")
            .with_dep("remote-complete"),
    );

    m.add_safety_property(SafetyProperty::new(
        "no_orphaned_evidence",
        "Evidence records reference a completed computation",
    ));
    m.add_safety_property(SafetyProperty::new(
        "no_exec_without_cap",
        "No remote execution without valid capability",
    ));
    m.add_safety_property(SafetyProperty::new(
        "evidence_before_release",
        "Evidence is committed before capability release finalizes",
    ));
    m
}

/// Build the lease_remote_conflict scenario model.
fn build_lease_remote_conflict() -> ProtocolModel {
    let mut m = ProtocolModel::new(
        ProtocolModelId::Custom(SCENARIO_LEASE_REMOTE_CONFLICT.into()),
        "Lease acquisition conflicting with remote capability operations",
    );
    m.add_operation(Operation::new(
        "lease-req-a",
        "tenant-a",
        "Tenant A requests lease",
    ));
    m.add_operation(Operation::new(
        "lease-req-b",
        "tenant-b",
        "Tenant B requests lease",
    ));
    m.add_operation(Operation::new(
        "remote-cap-check",
        "coordinator",
        "Check remote capability state",
    ));
    m.add_operation(
        Operation::new("lease-resolve", "coordinator", "Resolve lease conflict")
            .with_dep("lease-req-a")
            .with_dep("lease-req-b"),
    );
    m.add_operation(
        Operation::new("remote-cap-grant", "coordinator", "Grant remote capability")
            .with_dep("remote-cap-check")
            .with_dep("lease-resolve"),
    );

    m.add_safety_property(SafetyProperty::new(
        "no_dual_lease",
        "At most one tenant holds the lease at any time",
    ));
    m.add_safety_property(SafetyProperty::new(
        "cap_requires_lease",
        "Remote capability only granted to lease holder",
    ));
    m
}

/// Build the evidence_epoch_barrier scenario model.
fn build_evidence_epoch_barrier() -> ProtocolModel {
    let mut m = ProtocolModel::new(
        ProtocolModelId::Custom(SCENARIO_EVIDENCE_EPOCH_BARRIER.into()),
        "Evidence emission blocked by epoch barrier transitions",
    );
    m.add_operation(Operation::new(
        "evidence-prepare",
        "verifier",
        "Prepare evidence payload",
    ));
    m.add_operation(Operation::new(
        "epoch-barrier-raise",
        "leader",
        "Raise epoch barrier",
    ));
    m.add_operation(
        Operation::new("evidence-submit", "verifier", "Submit evidence to log")
            .with_dep("evidence-prepare"),
    );
    m.add_operation(
        Operation::new("epoch-barrier-drain", "leader", "Drain under barrier")
            .with_dep("epoch-barrier-raise"),
    );
    m.add_operation(
        Operation::new("evidence-finalize", "verifier", "Finalize evidence record")
            .with_dep("evidence-submit"),
    );
    m.add_operation(
        Operation::new("epoch-barrier-lower", "leader", "Lower epoch barrier")
            .with_dep("epoch-barrier-drain"),
    );
    m.add_operation(
        Operation::new(
            "evidence-confirm",
            "verifier",
            "Confirm evidence visible post-barrier",
        )
        .with_dep("evidence-finalize"),
    );

    m.add_safety_property(SafetyProperty::new(
        "evidence_epoch_consistent",
        "Evidence epoch tag matches the epoch in which it was finalized",
    ));
    m.add_safety_property(SafetyProperty::new(
        "no_lost_evidence",
        "No evidence record is silently dropped during barrier transitions",
    ));
    m
}

/// Build the epoch_remote_fence scenario model.
fn build_epoch_remote_fence() -> ProtocolModel {
    let mut m = ProtocolModel::new(
        ProtocolModelId::Custom(SCENARIO_EPOCH_REMOTE_FENCE.into()),
        "Epoch fencing token interactions with remote capability lifecycle",
    );
    m.add_operation(Operation::new(
        "fence-issue",
        "leader",
        "Issue fencing token",
    ));
    m.add_operation(Operation::new(
        "remote-acquire",
        "client",
        "Acquire remote capability",
    ));
    m.add_operation(
        Operation::new("fence-validate", "coordinator", "Validate fencing token")
            .with_dep("fence-issue"),
    );
    m.add_operation(
        Operation::new("remote-execute", "client", "Execute with capability")
            .with_dep("remote-acquire"),
    );
    m.add_operation(
        Operation::new(
            "fence-epoch-check",
            "coordinator",
            "Check fence epoch matches",
        )
        .with_dep("fence-validate"),
    );
    m.add_operation(
        Operation::new("remote-release", "client", "Release remote capability")
            .with_dep("remote-execute"),
    );
    m.add_operation(
        Operation::new("fence-retire", "leader", "Retire fencing token")
            .with_dep("fence-epoch-check"),
    );

    m.add_safety_property(SafetyProperty::new(
        "no_stale_write",
        "No write executes under a stale fencing token",
    ));
    m.add_safety_property(SafetyProperty::new(
        "fence_epoch_match",
        "Fencing token epoch matches active epoch at validation time",
    ));
    m.add_safety_property(SafetyProperty::new(
        "all_drain_before_commit",
        "All in-flight operations drain before epoch commit",
    ));
    m
}

/// Build the lease_evidence_sync scenario model.
fn build_lease_evidence_sync() -> ProtocolModel {
    let mut m = ProtocolModel::new(
        ProtocolModelId::Custom(SCENARIO_LEASE_EVIDENCE_SYNC.into()),
        "Lease lifecycle synchronized with evidence log operations",
    );
    m.add_operation(Operation::new("lease-acquire", "tenant", "Acquire lease"));
    m.add_operation(Operation::new(
        "evidence-log-open",
        "verifier",
        "Open evidence log session",
    ));
    m.add_operation(
        Operation::new("lease-use", "tenant", "Use leased resource").with_dep("lease-acquire"),
    );
    m.add_operation(
        Operation::new("evidence-append", "verifier", "Append evidence entry")
            .with_dep("evidence-log-open"),
    );
    m.add_operation(
        Operation::new("lease-release", "tenant", "Release lease").with_dep("lease-use"),
    );
    m.add_operation(
        Operation::new(
            "evidence-log-close",
            "verifier",
            "Close evidence log session",
        )
        .with_dep("evidence-append"),
    );

    m.add_safety_property(SafetyProperty::new(
        "evidence_covers_lease",
        "Evidence log session covers entire lease usage window",
    ));
    m.add_safety_property(SafetyProperty::new(
        "no_orphan_log",
        "No evidence log session outlives its associated lease",
    ));
    m
}

// ---------------------------------------------------------------------------
// DporScheduleGate
// ---------------------------------------------------------------------------

/// The DPOR schedule gate: registers and explores all six control-plane
/// interaction scenarios using the canonical upstream DporExplorer.
///
/// INV-DSG-CANONICAL: uses `DporExplorer` from `control_plane::dpor_exploration`.
pub struct DporScheduleGate {
    // Note: DporExplorer does not derive Debug, so we impl Debug manually below.
    explorer: DporExplorer,
    config: DporScheduleGateConfig,
    registered_scenarios: Vec<String>,
    events: Vec<GateEvent>,
}

impl std::fmt::Debug for DporScheduleGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DporScheduleGate")
            .field("config", &self.config)
            .field("registered_scenarios", &self.registered_scenarios)
            .field("events_count", &self.events.len())
            .finish_non_exhaustive()
    }
}

/// Structured event emitted during gate lifecycle.
#[derive(Debug, Clone)]
pub struct GateEvent {
    pub code: String,
    pub description: String,
    pub detail: String,
}

impl GateEvent {
    fn new(code: &str, detail: &str) -> Self {
        Self {
            code: code.to_string(),
            description: event_description(code).to_string(),
            detail: detail.to_string(),
        }
    }
}

impl DporScheduleGate {
    /// Create a new DPOR schedule gate with the given configuration.
    pub fn new(config: DporScheduleGateConfig) -> Result<Self, DporScheduleGateError> {
        config.validate()?;
        let budget = ExplorationBudget {
            time_seconds: config.time_budget_per_scenario_secs,
            memory_bytes: config.memory_budget_bytes,
        };
        let mut gate = Self {
            explorer: DporExplorer::new(budget),
            config,
            registered_scenarios: Vec::new(),
            events: Vec::new(),
        };
        gate.events
            .push(GateEvent::new(event_codes::DSG_001, "gate initialized"));
        Ok(gate)
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Result<Self, DporScheduleGateError> {
        Self::new(DporScheduleGateConfig::default())
    }

    /// Register all six canonical scenarios as exploration targets.
    pub fn register_all_scenarios(&mut self) -> Result<(), DporScheduleGateError> {
        let builders: ScenarioBuilderList<'_> = vec![
            (
                SCENARIO_EPOCH_LEASE_INTERLEAVE,
                build_epoch_lease_interleave,
            ),
            (SCENARIO_REMOTE_EVIDENCE_RACE, build_remote_evidence_race),
            (SCENARIO_LEASE_REMOTE_CONFLICT, build_lease_remote_conflict),
            (
                SCENARIO_EVIDENCE_EPOCH_BARRIER,
                build_evidence_epoch_barrier,
            ),
            (SCENARIO_EPOCH_REMOTE_FENCE, build_epoch_remote_fence),
            (SCENARIO_LEASE_EVIDENCE_SYNC, build_lease_evidence_sync),
        ];

        for (name, builder) in builders {
            let model = builder();
            self.explorer
                .register_model(model)
                .map_err(|e| DporScheduleGateError::RegistrationFailed(e.to_string()))?;
            self.registered_scenarios.push(name.to_string());
            self.events.push(GateEvent::new(
                event_codes::DSG_002,
                &format!("registered scenario: {}", name),
            ));
        }

        Ok(())
    }

    /// Register a single scenario by name.
    pub fn register_scenario(&mut self, name: &str) -> Result<(), DporScheduleGateError> {
        let model = match name {
            SCENARIO_EPOCH_LEASE_INTERLEAVE => build_epoch_lease_interleave(),
            SCENARIO_REMOTE_EVIDENCE_RACE => build_remote_evidence_race(),
            SCENARIO_LEASE_REMOTE_CONFLICT => build_lease_remote_conflict(),
            SCENARIO_EVIDENCE_EPOCH_BARRIER => build_evidence_epoch_barrier(),
            SCENARIO_EPOCH_REMOTE_FENCE => build_epoch_remote_fence(),
            SCENARIO_LEASE_EVIDENCE_SYNC => build_lease_evidence_sync(),
            _ => return Err(DporScheduleGateError::ScenarioNotFound(name.to_string())),
        };

        self.explorer
            .register_model(model)
            .map_err(|e| DporScheduleGateError::RegistrationFailed(e.to_string()))?;
        self.registered_scenarios.push(name.to_string());
        self.events.push(GateEvent::new(
            event_codes::DSG_002,
            &format!("registered scenario: {}", name),
        ));
        Ok(())
    }

    /// Get the list of registered scenario names.
    pub fn registered_scenarios(&self) -> &[String] {
        &self.registered_scenarios
    }

    /// Get the configuration.
    pub fn config(&self) -> &DporScheduleGateConfig {
        &self.config
    }

    /// Get emitted events.
    pub fn events(&self) -> &[GateEvent] {
        &self.events
    }

    /// Explore a single scenario with a custom safety checker.
    pub fn explore_scenario(
        &mut self,
        scenario_name: &str,
        check_fn: &dyn Fn(&[&Operation]) -> SafetyViolation,
    ) -> Result<ExplorationResult, DporScheduleGateError> {
        // Resolve the model name: ProtocolModelId::Custom display is "custom:<name>"
        let model_key = format!("custom:{}", scenario_name);

        self.events.push(GateEvent::new(
            event_codes::DSG_003,
            &format!("exploring scenario: {}", scenario_name),
        ));

        let trace_id = format!("dsg-{}", scenario_name);
        let result = self
            .explorer
            .explore(&model_key, check_fn, &trace_id)
            .map_err(|e| DporScheduleGateError::ExplorationFailed(e.to_string()))?;

        if result.budget_exceeded {
            self.events.push(GateEvent::new(
                event_codes::DSG_008,
                &format!("budget exceeded for scenario: {}", scenario_name),
            ));
        }

        if !result.violations.is_empty() {
            self.events.push(GateEvent::new(
                event_codes::DSG_005,
                &format!(
                    "violations found in {}: {}",
                    scenario_name,
                    result.violations.len()
                ),
            ));
        }

        self.events.push(GateEvent::new(
            event_codes::DSG_004,
            &format!(
                "completed {}: explored={}, violations={}",
                scenario_name,
                result.explored_count,
                result.violations.len()
            ),
        ));

        Ok(result)
    }

    /// Run the full gate across all registered scenarios using a safe
    /// (no-violation) checker. Returns a `GateResult` summarizing all
    /// exploration outcomes.
    ///
    /// INV-DSG-COVERAGE: all registered scenarios are explored.
    /// INV-DSG-BOUNDED: each scenario respects the configured budget.
    pub fn run_full_gate(&mut self) -> Result<GateResult, DporScheduleGateError> {
        if self.registered_scenarios.is_empty() {
            return Err(DporScheduleGateError::NoScenarios);
        }

        self.events.push(GateEvent::new(
            event_codes::DSG_006,
            &format!(
                "full gate run: {} scenarios",
                self.registered_scenarios.len()
            ),
        ));

        let scenario_names: Vec<String> = self.registered_scenarios.clone();
        let mut per_scenario = Vec::new();
        let mut total_schedules: u64 = 0;
        let mut total_violations: usize = 0;

        let no_violation_checker =
            |_ops: &[&Operation]| -> Option<(String, Vec<CounterexampleStep>)> { None };

        for name in &scenario_names {
            let result = self.explore_scenario(name, &no_violation_checker)?;
            total_schedules += result.explored_count;
            total_violations += result.violations.len();
            per_scenario.push(result);
        }

        let verdict = if total_violations == 0 {
            "PASS".to_string()
        } else {
            "FAIL".to_string()
        };

        self.events.push(GateEvent::new(
            event_codes::DSG_007,
            &format!(
                "full gate complete: schedules={}, violations={}, verdict={}",
                total_schedules, total_violations, verdict
            ),
        ));

        Ok(GateResult {
            schema_version: SCHEMA_VERSION.to_string(),
            scenarios_explored: per_scenario.len(),
            scenarios_total: ALL_SCENARIOS.len(),
            total_schedules_explored: total_schedules,
            total_violations,
            per_scenario,
            verdict,
        })
    }

    /// Run the full gate with a custom per-scenario checker map.
    pub fn run_full_gate_with_checker(
        &mut self,
        check_fn: &dyn Fn(&[&Operation]) -> SafetyViolation,
    ) -> Result<GateResult, DporScheduleGateError> {
        if self.registered_scenarios.is_empty() {
            return Err(DporScheduleGateError::NoScenarios);
        }

        self.events.push(GateEvent::new(
            event_codes::DSG_006,
            &format!(
                "full gate run (custom checker): {} scenarios",
                self.registered_scenarios.len()
            ),
        ));

        let scenario_names: Vec<String> = self.registered_scenarios.clone();
        let mut per_scenario = Vec::new();
        let mut total_schedules: u64 = 0;
        let mut total_violations: usize = 0;

        for name in &scenario_names {
            let result = self.explore_scenario(name, check_fn)?;
            total_schedules += result.explored_count;
            total_violations += result.violations.len();
            per_scenario.push(result);
        }

        let verdict = if total_violations == 0 {
            "PASS".to_string()
        } else {
            "FAIL".to_string()
        };

        self.events.push(GateEvent::new(
            event_codes::DSG_007,
            &format!(
                "full gate complete: schedules={}, violations={}, verdict={}",
                total_schedules, total_violations, verdict
            ),
        ));

        Ok(GateResult {
            schema_version: SCHEMA_VERSION.to_string(),
            scenarios_explored: per_scenario.len(),
            scenarios_total: ALL_SCENARIOS.len(),
            total_schedules_explored: total_schedules,
            total_violations,
            per_scenario,
            verdict,
        })
    }

    /// Access the underlying explorer (for audit log inspection, etc.)
    pub fn explorer(&self) -> &DporExplorer {
        &self.explorer
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn no_violations(_ops: &[&Operation]) -> Option<(String, Vec<CounterexampleStep>)> {
        None
    }

    fn always_violate(_ops: &[&Operation]) -> Option<(String, Vec<CounterexampleStep>)> {
        Some((
            "injected_violation".to_string(),
            vec![CounterexampleStep {
                step_index: 0,
                operation_id: "injected".to_string(),
                actor: "adversary".to_string(),
                state_summary: "deliberately violated".to_string(),
            }],
        ))
    }

    fn make_gate() -> DporScheduleGate {
        let mut gate = DporScheduleGate::with_defaults().unwrap();
        gate.register_all_scenarios().unwrap();
        gate
    }

    // --- 1. Gate initialization ---

    #[test]
    fn gate_initializes_with_defaults() {
        let gate = DporScheduleGate::with_defaults().unwrap();
        assert_eq!(gate.config().time_budget_per_scenario_secs, 120);
        assert_eq!(gate.config().memory_budget_bytes, 1_073_741_824);
        assert!(gate.registered_scenarios().is_empty());
    }

    // --- 2. Invalid config rejected ---

    #[test]
    fn invalid_config_zero_time_rejected() {
        let config = DporScheduleGateConfig {
            time_budget_per_scenario_secs: 0,
            memory_budget_bytes: 1_073_741_824,
        };
        let err = DporScheduleGate::new(config).unwrap_err();
        assert_eq!(err.code(), ERR_DSG_INVALID_CONFIG);
    }

    // --- 3. Invalid config zero memory rejected ---

    #[test]
    fn invalid_config_zero_memory_rejected() {
        let config = DporScheduleGateConfig {
            time_budget_per_scenario_secs: 60,
            memory_budget_bytes: 0,
        };
        let err = DporScheduleGate::new(config).unwrap_err();
        assert_eq!(err.code(), ERR_DSG_INVALID_CONFIG);
    }

    // --- 4. All six scenarios register ---

    #[test]
    fn all_six_scenarios_registered() {
        let gate = make_gate();
        assert_eq!(gate.registered_scenarios().len(), 6);
        for name in ALL_SCENARIOS {
            assert!(
                gate.registered_scenarios().contains(&name.to_string()),
                "missing scenario: {}",
                name
            );
        }
    }

    // --- 5. Single scenario registration ---

    #[test]
    fn register_single_scenario() {
        let mut gate = DporScheduleGate::with_defaults().unwrap();
        gate.register_scenario(SCENARIO_EPOCH_LEASE_INTERLEAVE)
            .unwrap();
        assert_eq!(gate.registered_scenarios().len(), 1);
        assert_eq!(
            gate.registered_scenarios()[0],
            SCENARIO_EPOCH_LEASE_INTERLEAVE
        );
    }

    // --- 6. Unknown scenario rejected ---

    #[test]
    fn unknown_scenario_rejected() {
        let mut gate = DporScheduleGate::with_defaults().unwrap();
        let err = gate.register_scenario("nonexistent").unwrap_err();
        assert_eq!(err.code(), ERR_DSG_SCENARIO_NOT_FOUND);
    }

    // --- 7. Full gate run passes with no violations ---

    #[test]
    fn full_gate_no_violations() {
        let mut gate = make_gate();
        let result = gate.run_full_gate().unwrap();
        assert!(result.is_pass());
        assert_eq!(result.verdict, "PASS");
        assert_eq!(result.scenarios_explored, 6);
        assert_eq!(result.total_violations, 0);
        assert!(result.total_schedules_explored > 0);
    }

    // --- 8. Full gate with injected violations ---

    #[test]
    fn full_gate_with_violations() {
        let mut gate = make_gate();
        let result = gate.run_full_gate_with_checker(&always_violate).unwrap();
        assert!(!result.is_pass());
        assert_eq!(result.verdict, "FAIL");
        assert!(result.total_violations > 0);
    }

    // --- 9. Run gate with no scenarios fails ---

    #[test]
    fn run_gate_no_scenarios_fails() {
        let mut gate = DporScheduleGate::with_defaults().unwrap();
        let err = gate.run_full_gate().unwrap_err();
        assert_eq!(err.code(), ERR_DSG_NO_SCENARIOS);
    }

    // --- 10. Explore single scenario passes ---

    #[test]
    fn explore_single_scenario_passes() {
        let mut gate = make_gate();
        let result = gate
            .explore_scenario(SCENARIO_EPOCH_LEASE_INTERLEAVE, &no_violations)
            .unwrap();
        assert!(result.is_pass());
        assert!(result.explored_count > 0);
    }

    // --- 11. Explore single scenario with violation ---

    #[test]
    fn explore_single_scenario_violation() {
        let mut gate = make_gate();
        let result = gate
            .explore_scenario(SCENARIO_REMOTE_EVIDENCE_RACE, &always_violate)
            .unwrap();
        assert!(!result.is_pass());
        assert!(!result.violations.is_empty());
    }

    // --- 12. Schema version ---

    #[test]
    fn schema_version_is_dsg_v1() {
        assert_eq!(SCHEMA_VERSION, "dsg-v1.0");
    }

    // --- 13. Gate result schema version ---

    #[test]
    fn gate_result_has_schema_version() {
        let mut gate = make_gate();
        let result = gate.run_full_gate().unwrap();
        assert_eq!(result.schema_version, SCHEMA_VERSION);
    }

    // --- 14. Event codes emitted during gate lifecycle ---

    #[test]
    fn events_emitted_during_lifecycle() {
        let mut gate = make_gate();
        gate.run_full_gate().unwrap();
        let codes: Vec<&str> = gate.events().iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&event_codes::DSG_001)); // initialized
        assert!(codes.contains(&event_codes::DSG_002)); // registered
        assert!(codes.contains(&event_codes::DSG_003)); // exploration started
        assert!(codes.contains(&event_codes::DSG_004)); // exploration completed
        assert!(codes.contains(&event_codes::DSG_006)); // full gate started
        assert!(codes.contains(&event_codes::DSG_007)); // full gate completed
    }

    // --- 15. Violation events emitted ---

    #[test]
    fn violation_events_emitted() {
        let mut gate = make_gate();
        gate.run_full_gate_with_checker(&always_violate).unwrap();
        let codes: Vec<&str> = gate.events().iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&event_codes::DSG_005)); // violation found
    }

    // --- 16. Event description lookup ---

    #[test]
    fn event_descriptions_valid() {
        assert_eq!(
            event_description(event_codes::DSG_001),
            "schedule gate initialized"
        );
        assert_eq!(
            event_description(event_codes::DSG_005),
            "violation found — counterexample emitted"
        );
        assert_eq!(event_description("unknown"), "unknown event code");
    }

    // --- 17. Error display includes code ---

    #[test]
    fn error_display_includes_code() {
        let errors: Vec<DporScheduleGateError> = vec![
            DporScheduleGateError::NoScenarios,
            DporScheduleGateError::RegistrationFailed("detail".into()),
            DporScheduleGateError::ExplorationFailed("detail".into()),
            DporScheduleGateError::BudgetExceeded {
                scenario: "s".into(),
            },
            DporScheduleGateError::ScenarioNotFound("s".into()),
            DporScheduleGateError::SafetyViolation {
                scenario: "s".into(),
                property: "p".into(),
            },
            DporScheduleGateError::IncompleteCoverage {
                explored: 3,
                expected: 6,
            },
            DporScheduleGateError::InvalidConfig("detail".into()),
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(
                s.contains(e.code()),
                "error display '{}' should contain code '{}'",
                s,
                e.code()
            );
        }
    }

    // --- 18. Invariant constants are distinct ---

    #[test]
    fn invariant_constants_distinct() {
        let invs = [
            INV_DSG_CANONICAL,
            INV_DSG_BOUNDED,
            INV_DSG_COVERAGE,
            INV_DSG_COUNTEREXAMPLE,
            INV_DSG_DETERMINISTIC,
            INV_DSG_SAFETY,
        ];
        let unique: std::collections::HashSet<&str> = invs.iter().copied().collect();
        assert_eq!(unique.len(), invs.len());
    }

    // --- 19. All scenarios constant ---

    #[test]
    fn all_scenarios_constant_complete() {
        assert_eq!(ALL_SCENARIOS.len(), 6);
        assert!(ALL_SCENARIOS.contains(&SCENARIO_EPOCH_LEASE_INTERLEAVE));
        assert!(ALL_SCENARIOS.contains(&SCENARIO_REMOTE_EVIDENCE_RACE));
        assert!(ALL_SCENARIOS.contains(&SCENARIO_LEASE_REMOTE_CONFLICT));
        assert!(ALL_SCENARIOS.contains(&SCENARIO_EVIDENCE_EPOCH_BARRIER));
        assert!(ALL_SCENARIOS.contains(&SCENARIO_EPOCH_REMOTE_FENCE));
        assert!(ALL_SCENARIOS.contains(&SCENARIO_LEASE_EVIDENCE_SYNC));
    }

    // --- 20. Per-scenario results in gate result ---

    #[test]
    fn gate_result_per_scenario_populated() {
        let mut gate = make_gate();
        let result = gate.run_full_gate().unwrap();
        assert_eq!(result.per_scenario.len(), 6);
        for sr in &result.per_scenario {
            assert!(sr.is_pass());
            assert!(sr.explored_count > 0);
        }
    }

    // --- 21. Audit log accessible through explorer ---

    #[test]
    fn audit_log_accessible() {
        let mut gate = make_gate();
        gate.run_full_gate().unwrap();
        let audit = gate.explorer().audit_log();
        assert!(!audit.is_empty());
    }

    // --- 22. Deterministic exploration (INV-DSG-DETERMINISTIC) ---

    #[test]
    fn deterministic_exploration() {
        let mut gate1 = make_gate();
        let r1 = gate1.run_full_gate().unwrap();

        let mut gate2 = make_gate();
        let r2 = gate2.run_full_gate().unwrap();

        assert_eq!(r1.total_schedules_explored, r2.total_schedules_explored);
        assert_eq!(r1.total_violations, r2.total_violations);
        assert_eq!(r1.verdict, r2.verdict);
        for (s1, s2) in r1.per_scenario.iter().zip(r2.per_scenario.iter()) {
            assert_eq!(s1.explored_count, s2.explored_count);
        }
    }
}
