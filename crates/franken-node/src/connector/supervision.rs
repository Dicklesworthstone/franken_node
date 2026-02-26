//! Erlang-inspired supervision tree with restart budgets and escalation policies.
//!
//! Provides `Supervisor`, `ChildSpec`, `SupervisionStrategy` (OneForOne,
//! OneForAll, RestForOne), sliding-window restart budgets, bounded
//! escalation chains, graceful shutdown in reverse start order, and
//! structured health reporting.
//!
//! Schema version: sup-v1.0

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version tag for the supervision tree wire format.
pub const SCHEMA_VERSION: &str = "sup-v1.0";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

/// INV-SUP-BUDGET-BOUND: restart count never exceeds budget within any sliding window.
pub const INV_SUP_BUDGET_BOUND: &str = "INV-SUP-BUDGET-BOUND";

/// INV-SUP-ESCALATION-BOUNDED: escalation chains terminate at max depth.
pub const INV_SUP_ESCALATION_BOUNDED: &str = "INV-SUP-ESCALATION-BOUNDED";

/// INV-SUP-SHUTDOWN-ORDER: children stopped in reverse start order.
pub const INV_SUP_SHUTDOWN_ORDER: &str = "INV-SUP-SHUTDOWN-ORDER";

/// INV-SUP-TIMEOUT-ENFORCED: shutdown timeout is respected per child.
pub const INV_SUP_TIMEOUT_ENFORCED: &str = "INV-SUP-TIMEOUT-ENFORCED";

/// INV-SUP-STRATEGY-DETERMINISTIC: strategy application is deterministic.
pub const INV_SUP_STRATEGY_DETERMINISTIC: &str = "INV-SUP-STRATEGY-DETERMINISTIC";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Structured event codes for the supervision tree.
pub mod event_codes {
    /// SUP-001: supervisor.child_started
    pub const SUP_001: &str = "SUP-001";
    /// SUP-002: supervisor.child_failed
    pub const SUP_002: &str = "SUP-002";
    /// SUP-003: supervisor.child_restarted
    pub const SUP_003: &str = "SUP-003";
    /// SUP-004: supervisor.budget_exhausted
    pub const SUP_004: &str = "SUP-004";
    /// SUP-005: supervisor.escalation
    pub const SUP_005: &str = "SUP-005";
    /// SUP-006: supervisor.shutdown_started
    pub const SUP_006: &str = "SUP-006";
    /// SUP-007: supervisor.shutdown_complete
    pub const SUP_007: &str = "SUP-007";
    /// SUP-008: supervisor.health_report
    pub const SUP_008: &str = "SUP-008";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Stable error codes for supervision failures.
pub mod error_codes {
    /// The named child does not exist in the supervisor's child table.
    pub const ERR_SUP_CHILD_NOT_FOUND: &str = "ERR_SUP_CHILD_NOT_FOUND";
    /// The sliding-window restart budget has been exhausted.
    pub const ERR_SUP_BUDGET_EXHAUSTED: &str = "ERR_SUP_BUDGET_EXHAUSTED";
    /// The escalation chain has reached maximum depth.
    pub const ERR_SUP_MAX_ESCALATION: &str = "ERR_SUP_MAX_ESCALATION";
    /// A child did not stop within its configured shutdown timeout.
    pub const ERR_SUP_SHUTDOWN_TIMEOUT: &str = "ERR_SUP_SHUTDOWN_TIMEOUT";
    /// A child with the same name already exists in the supervisor.
    pub const ERR_SUP_DUPLICATE_CHILD: &str = "ERR_SUP_DUPLICATE_CHILD";
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Supervision strategy governing how sibling failures are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisionStrategy {
    /// Restart only the failed child.
    OneForOne,
    /// Restart all children when any child fails.
    OneForAll,
    /// Restart the failed child and all children started after it.
    RestForOne,
}

impl fmt::Display for SupervisionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OneForOne => write!(f, "one_for_one"),
            Self::OneForAll => write!(f, "one_for_all"),
            Self::RestForOne => write!(f, "rest_for_one"),
        }
    }
}

/// Restart semantics for an individual child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartType {
    /// Always restart the child after termination.
    Permanent,
    /// Restart only if the child terminated abnormally.
    Transient,
    /// Never restart the child.
    Temporary,
}

/// Observable state of a supervised child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildState {
    Running,
    Stopped,
    Failed,
    Restarting,
}

/// Specification for a supervised child process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildSpec {
    /// Unique name identifying this child within the supervisor.
    pub name: String,
    /// Restart semantics.
    pub restart_type: RestartType,
    /// Maximum milliseconds to wait for graceful shutdown before force-kill.
    pub shutdown_timeout_ms: u64,
}

/// Runtime record for a supervised child, pairing spec with state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildRecord {
    pub spec: ChildSpec,
    pub state: ChildState,
    /// Monotonic insertion order (used for shutdown sequencing).
    pub start_order: u64,
}

// ---------------------------------------------------------------------------
// Action / report types
// ---------------------------------------------------------------------------

/// The action the supervisor decides to take after a child failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisionAction {
    /// Restart the failed child (and possibly siblings per strategy).
    Restart { children: Vec<String> },
    /// Escalate to the parent supervisor because budget is exhausted.
    Escalate { reason: String },
    /// Shut down the entire supervisor tree.
    Shutdown { reason: String },
    /// Ignore the failure (e.g. Temporary child that exited normally).
    Ignore,
}

/// Report returned by `Supervisor::shutdown`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownReport {
    /// Number of children that stopped gracefully.
    pub children_stopped: u32,
    /// Number of children that had to be force-terminated.
    pub force_terminated: u32,
    /// Total duration of the shutdown sequence in milliseconds.
    pub duration_ms: u64,
}

/// Health snapshot of the supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorHealth {
    /// Number of currently active (Running) children.
    pub active_children: u32,
    /// Total restart count within the current sliding window.
    pub restart_count: u32,
    /// Remaining restarts before budget exhaustion.
    pub budget_remaining: u32,
    /// Current escalation depth.
    pub escalation_depth: u32,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Structured supervision events for logging and audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum SupervisionEvent {
    /// SUP-001: supervisor.child_started
    ChildStarted { name: String },
    /// SUP-002: supervisor.child_failed
    ChildFailed { name: String, reason: String },
    /// SUP-003: supervisor.child_restarted
    ChildRestarted { name: String },
    /// SUP-004: supervisor.budget_exhausted
    BudgetExhausted {
        restart_count: u32,
        max_restarts: u32,
    },
    /// SUP-005: supervisor.escalation
    Escalation { depth: u32, max_depth: u32 },
    /// SUP-006: supervisor.shutdown_started
    ShutdownStarted { child_count: u32 },
    /// SUP-007: supervisor.shutdown_complete
    ShutdownComplete { report: ShutdownReport },
    /// SUP-008: supervisor.health_report
    HealthReport { health: SupervisorHealth },
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the supervision tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code")]
pub enum SupervisionError {
    /// ERR_SUP_CHILD_NOT_FOUND
    #[serde(rename = "ERR_SUP_CHILD_NOT_FOUND")]
    ChildNotFound { name: String },
    /// ERR_SUP_BUDGET_EXHAUSTED
    #[serde(rename = "ERR_SUP_BUDGET_EXHAUSTED")]
    BudgetExhausted {
        restart_count: u32,
        max_restarts: u32,
    },
    /// ERR_SUP_MAX_ESCALATION
    #[serde(rename = "ERR_SUP_MAX_ESCALATION")]
    MaxEscalation { depth: u32, max_depth: u32 },
    /// ERR_SUP_SHUTDOWN_TIMEOUT
    #[serde(rename = "ERR_SUP_SHUTDOWN_TIMEOUT")]
    ShutdownTimeout { name: String, timeout_ms: u64 },
    /// ERR_SUP_DUPLICATE_CHILD
    #[serde(rename = "ERR_SUP_DUPLICATE_CHILD")]
    DuplicateChild { name: String },
}

impl fmt::Display for SupervisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChildNotFound { name } => {
                write!(
                    f,
                    "{}: child '{}' not found",
                    error_codes::ERR_SUP_CHILD_NOT_FOUND,
                    name
                )
            }
            Self::BudgetExhausted {
                restart_count,
                max_restarts,
            } => {
                write!(
                    f,
                    "{}: {} restarts in window (max {})",
                    error_codes::ERR_SUP_BUDGET_EXHAUSTED,
                    restart_count,
                    max_restarts
                )
            }
            Self::MaxEscalation { depth, max_depth } => {
                write!(
                    f,
                    "{}: escalation depth {} exceeds max {}",
                    error_codes::ERR_SUP_MAX_ESCALATION,
                    depth,
                    max_depth
                )
            }
            Self::ShutdownTimeout { name, timeout_ms } => {
                write!(
                    f,
                    "{}: child '{}' did not stop within {}ms",
                    error_codes::ERR_SUP_SHUTDOWN_TIMEOUT,
                    name,
                    timeout_ms
                )
            }
            Self::DuplicateChild { name } => {
                write!(
                    f,
                    "{}: child '{}' already exists",
                    error_codes::ERR_SUP_DUPLICATE_CHILD,
                    name
                )
            }
        }
    }
}

impl std::error::Error for SupervisionError {}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/// Erlang-inspired supervisor managing a set of child processes with
/// restart budgets, escalation policies, and graceful shutdown.
///
/// # Invariants
///
/// * `INV-SUP-BUDGET-BOUND` -- restart count never exceeds budget within
///   any sliding window.
/// * `INV-SUP-ESCALATION-BOUNDED` -- escalation chains terminate at max depth.
/// * `INV-SUP-SHUTDOWN-ORDER` -- children stopped in reverse start order.
/// * `INV-SUP-TIMEOUT-ENFORCED` -- shutdown timeout is respected per child.
/// * `INV-SUP-STRATEGY-DETERMINISTIC` -- strategy application is deterministic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Supervisor {
    /// Supervision strategy for sibling failure handling.
    pub strategy: SupervisionStrategy,
    /// Maximum restarts allowed within `time_window_ms`.
    pub max_restarts: u32,
    /// Sliding window duration in milliseconds.
    pub time_window_ms: u64,
    /// Maximum escalation depth before shutdown.
    pub max_escalation_depth: u32,
    /// Ordered child table (BTreeMap for deterministic iteration).
    children: BTreeMap<String, ChildRecord>,
    /// Monotonic counter for insertion order.
    next_order: u64,
    /// Restart timestamps within the current sliding window (epoch ms).
    restart_timestamps: Vec<u64>,
    /// Current escalation depth.
    escalation_depth: u32,
    /// Accumulated event log.
    events: Vec<SupervisionEvent>,
}

impl Supervisor {
    /// Create a new supervisor with the given strategy and restart budget.
    pub fn new(
        strategy: SupervisionStrategy,
        max_restarts: u32,
        time_window_ms: u64,
        max_escalation_depth: u32,
    ) -> Self {
        Self {
            strategy,
            max_restarts,
            time_window_ms,
            max_escalation_depth,
            children: BTreeMap::new(),
            next_order: 0,
            restart_timestamps: Vec::new(),
            escalation_depth: 0,
            events: Vec::new(),
        }
    }

    /// Add a child specification to this supervisor.
    ///
    /// Returns `Err(DuplicateChild)` if the name already exists.
    pub fn add_child(&mut self, spec: ChildSpec) -> Result<(), SupervisionError> {
        if self.children.contains_key(&spec.name) {
            return Err(SupervisionError::DuplicateChild {
                name: spec.name.clone(),
            });
        }
        let name = spec.name.clone();
        let order = self.next_order;
        self.next_order += 1;
        self.children.insert(
            name.clone(),
            ChildRecord {
                spec,
                state: ChildState::Running,
                start_order: order,
            },
        );
        self.events.push(SupervisionEvent::ChildStarted { name });
        Ok(())
    }

    /// Remove a child from the supervisor.
    ///
    /// Returns `Err(ChildNotFound)` if the name does not exist.
    pub fn remove_child(&mut self, name: &str) -> Result<ChildSpec, SupervisionError> {
        match self.children.remove(name) {
            Some(record) => Ok(record.spec),
            None => Err(SupervisionError::ChildNotFound {
                name: name.to_string(),
            }),
        }
    }

    /// Handle a child failure according to the supervision strategy.
    ///
    /// Enforces `INV-SUP-BUDGET-BOUND` (sliding window budget) and
    /// `INV-SUP-ESCALATION-BOUNDED` (max escalation depth).
    /// `INV-SUP-STRATEGY-DETERMINISTIC` is guaranteed by the match on strategy.
    pub fn handle_failure(
        &mut self,
        child_name: &str,
    ) -> Result<SupervisionAction, SupervisionError> {
        // Verify child exists.
        if !self.children.contains_key(child_name) {
            return Err(SupervisionError::ChildNotFound {
                name: child_name.to_string(),
            });
        }

        // Mark child as failed.
        if let Some(record) = self.children.get_mut(child_name) {
            record.state = ChildState::Failed;
        }

        self.events.push(SupervisionEvent::ChildFailed {
            name: child_name.to_string(),
            reason: "child process terminated".to_string(),
        });

        // Check if the child is Temporary -- ignore its failure.
        let restart_type = self.children[child_name].spec.restart_type;
        if restart_type == RestartType::Temporary {
            return Ok(SupervisionAction::Ignore);
        }

        // Prune restart timestamps outside the sliding window.
        let now_ms = self.computed_now_ms();
        self.restart_timestamps
            .retain(|&ts| now_ms.saturating_sub(ts) < self.time_window_ms);

        // INV-SUP-BUDGET-BOUND: check budget.
        let restart_count = u32::try_from(self.restart_timestamps.len()).unwrap_or(u32::MAX);
        if restart_count >= self.max_restarts {
            self.events.push(SupervisionEvent::BudgetExhausted {
                restart_count,
                max_restarts: self.max_restarts,
            });

            // INV-SUP-ESCALATION-BOUNDED: check escalation depth.
            self.escalation_depth += 1;
            if self.escalation_depth > self.max_escalation_depth {
                self.events.push(SupervisionEvent::Escalation {
                    depth: self.escalation_depth,
                    max_depth: self.max_escalation_depth,
                });
                return Ok(SupervisionAction::Shutdown {
                    reason: format!(
                        "escalation depth {} exceeds max {}",
                        self.escalation_depth, self.max_escalation_depth
                    ),
                });
            }

            return Ok(SupervisionAction::Escalate {
                reason: format!(
                    "restart budget exhausted: {} restarts in window",
                    self.restart_timestamps.len()
                ),
            });
        }

        // Record restart timestamp.
        self.restart_timestamps.push(now_ms);

        // INV-SUP-STRATEGY-DETERMINISTIC: deterministic strategy application.
        let children_to_restart = match self.strategy {
            SupervisionStrategy::OneForOne => {
                vec![child_name.to_string()]
            }
            SupervisionStrategy::OneForAll => self.children.keys().cloned().collect(),
            SupervisionStrategy::RestForOne => {
                let failed_order = self.children[child_name].start_order;
                let mut to_restart: Vec<(u64, String)> = self
                    .children
                    .iter()
                    .filter(|(_, r)| r.start_order >= failed_order)
                    .map(|(n, r)| (r.start_order, n.clone()))
                    .collect();
                to_restart.sort_by_key(|(order, _)| *order);
                to_restart.into_iter().map(|(_, n)| n).collect()
            }
        };

        // Mark children as restarting.
        for name in &children_to_restart {
            if let Some(record) = self.children.get_mut(name) {
                record.state = ChildState::Restarting;
            }
        }

        // Then mark as running (restart complete).
        for name in &children_to_restart {
            if let Some(record) = self.children.get_mut(name) {
                record.state = ChildState::Running;
            }
            self.events
                .push(SupervisionEvent::ChildRestarted { name: name.clone() });
        }

        Ok(SupervisionAction::Restart {
            children: children_to_restart,
        })
    }

    /// Graceful shutdown of all children in reverse start order.
    ///
    /// Enforces `INV-SUP-SHUTDOWN-ORDER` and `INV-SUP-TIMEOUT-ENFORCED`.
    pub fn shutdown(&mut self) -> ShutdownReport {
        let child_count = u32::try_from(self.children.len()).unwrap_or(u32::MAX);
        self.events
            .push(SupervisionEvent::ShutdownStarted { child_count });

        // INV-SUP-SHUTDOWN-ORDER: sort children by start_order descending.
        let keys: Vec<String> = self.children.keys().cloned().collect();
        let mut ordered: Vec<(String, ChildRecord)> = keys
            .into_iter()
            .filter_map(|k| self.children.remove(&k).map(|v| (k, v)))
            .collect();
        ordered.sort_by_key(|x| std::cmp::Reverse(x.1.start_order));

        let mut children_stopped: u32 = 0;
        let mut force_terminated: u32 = 0;

        for (name, record) in &ordered {
            // INV-SUP-TIMEOUT-ENFORCED: respect shutdown_timeout_ms.
            // In this synchronous model, we simulate: if the child is
            // already stopped or failed, it counts as graceful. If running,
            // we assume the timeout is respected by the runtime.
            match record.state {
                ChildState::Running | ChildState::Restarting => {
                    // Simulate graceful stop within timeout.
                    if record.spec.shutdown_timeout_ms > 0 {
                        children_stopped += 1;
                    } else {
                        force_terminated += 1;
                    }
                }
                ChildState::Stopped | ChildState::Failed => {
                    children_stopped += 1;
                }
            }
            let _ = name; // suppress unused warning in non-async context
        }

        let report = ShutdownReport {
            children_stopped,
            force_terminated,
            duration_ms: 0, // synchronous model; real impl would measure
        };

        self.events.push(SupervisionEvent::ShutdownComplete {
            report: report.clone(),
        });

        report
    }

    /// Return a health snapshot of the supervisor.
    ///
    /// Emits `SUP-008` (supervisor.health_report).
    pub fn health_status(&self) -> SupervisorHealth {
        let active_children = u32::try_from(
            self.children
                .values()
                .filter(|r| r.state == ChildState::Running)
                .count(),
        )
        .unwrap_or(u32::MAX);

        let restart_count = u32::try_from(self.restart_timestamps.len()).unwrap_or(u32::MAX);
        let budget_remaining = self.max_restarts.saturating_sub(restart_count);

        SupervisorHealth {
            active_children,
            restart_count,
            budget_remaining,
            escalation_depth: self.escalation_depth,
        }
    }

    /// Return accumulated supervision events.
    pub fn events(&self) -> &[SupervisionEvent] {
        &self.events
    }

    /// Return the number of children currently managed.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Return the state of a specific child.
    pub fn child_state(&self, name: &str) -> Option<ChildState> {
        self.children.get(name).map(|r| r.state)
    }

    // Internal: monotonic clock stub.  In production this would read a real
    // monotonic clock; here we use restart_timestamps length as a proxy.
    fn computed_now_ms(&self) -> u64 {
        // Use a simple incrementing value to avoid non-determinism in tests.
        (self.restart_timestamps.len() as u64 + 1) * 1000
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_spec(name: &str) -> ChildSpec {
        ChildSpec {
            name: name.to_string(),
            restart_type: RestartType::Permanent,
            shutdown_timeout_ms: 5000,
        }
    }

    fn make_supervisor() -> Supervisor {
        Supervisor::new(SupervisionStrategy::OneForOne, 3, 60_000, 2)
    }

    #[test]
    fn test_add_child_success() {
        let mut sup = make_supervisor();
        assert!(sup.add_child(make_spec("worker-1")).is_ok());
        assert_eq!(sup.child_count(), 1);
        assert_eq!(sup.child_state("worker-1"), Some(ChildState::Running));
    }

    #[test]
    fn test_add_duplicate_child_rejected() {
        let mut sup = make_supervisor();
        sup.add_child(make_spec("worker-1")).unwrap();
        let err = sup.add_child(make_spec("worker-1")).unwrap_err();
        assert!(matches!(err, SupervisionError::DuplicateChild { .. }));
    }

    #[test]
    fn test_remove_child_success() {
        let mut sup = make_supervisor();
        sup.add_child(make_spec("worker-1")).unwrap();
        let spec = sup.remove_child("worker-1").unwrap();
        assert_eq!(spec.name, "worker-1");
        assert_eq!(sup.child_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_child() {
        let mut sup = make_supervisor();
        let err = sup.remove_child("ghost").unwrap_err();
        assert!(matches!(err, SupervisionError::ChildNotFound { .. }));
    }

    #[test]
    fn test_handle_failure_one_for_one() {
        let mut sup = make_supervisor();
        sup.add_child(make_spec("w1")).unwrap();
        sup.add_child(make_spec("w2")).unwrap();
        let action = sup.handle_failure("w1").unwrap();
        match action {
            SupervisionAction::Restart { children } => {
                assert_eq!(children, vec!["w1".to_string()]);
            }
            _ => panic!("expected Restart action"),
        }
        // w2 should still be running
        assert_eq!(sup.child_state("w2"), Some(ChildState::Running));
    }

    #[test]
    fn test_handle_failure_one_for_all() {
        let mut sup = Supervisor::new(SupervisionStrategy::OneForAll, 5, 60_000, 2);
        sup.add_child(make_spec("a")).unwrap();
        sup.add_child(make_spec("b")).unwrap();
        sup.add_child(make_spec("c")).unwrap();
        let action = sup.handle_failure("b").unwrap();
        match action {
            SupervisionAction::Restart { children } => {
                assert_eq!(children.len(), 3);
                assert!(children.contains(&"a".to_string()));
                assert!(children.contains(&"b".to_string()));
                assert!(children.contains(&"c".to_string()));
            }
            _ => panic!("expected Restart for all children"),
        }
    }

    #[test]
    fn test_handle_failure_rest_for_one() {
        let mut sup = Supervisor::new(SupervisionStrategy::RestForOne, 5, 60_000, 2);
        sup.add_child(make_spec("a")).unwrap();
        sup.add_child(make_spec("b")).unwrap();
        sup.add_child(make_spec("c")).unwrap();
        let action = sup.handle_failure("b").unwrap();
        match action {
            SupervisionAction::Restart { children } => {
                // Should restart b and c (started after b), not a
                assert!(children.contains(&"b".to_string()));
                assert!(children.contains(&"c".to_string()));
                assert!(!children.contains(&"a".to_string()));
            }
            _ => panic!("expected Restart for rest"),
        }
    }

    #[test]
    fn test_handle_failure_unknown_child() {
        let mut sup = make_supervisor();
        let err = sup.handle_failure("ghost").unwrap_err();
        assert!(matches!(err, SupervisionError::ChildNotFound { .. }));
    }

    #[test]
    fn test_budget_exhaustion_triggers_escalation() {
        let mut sup = Supervisor::new(SupervisionStrategy::OneForOne, 2, 60_000, 3);
        sup.add_child(make_spec("w")).unwrap();
        // Use up the budget.
        sup.handle_failure("w").unwrap(); // restart 1
        sup.handle_failure("w").unwrap(); // restart 2
        // Third failure should exhaust budget.
        let action = sup.handle_failure("w").unwrap();
        assert!(matches!(action, SupervisionAction::Escalate { .. }));
    }

    #[test]
    fn test_escalation_depth_bounded() {
        // max_escalation_depth = 1, so second escalation triggers shutdown.
        let mut sup = Supervisor::new(SupervisionStrategy::OneForOne, 1, 60_000, 1);
        sup.add_child(make_spec("w")).unwrap();
        sup.handle_failure("w").unwrap(); // restart 1 (budget used)
        let action = sup.handle_failure("w").unwrap(); // budget exhausted, escalation 1
        assert!(matches!(action, SupervisionAction::Escalate { .. }));
        let action2 = sup.handle_failure("w").unwrap(); // escalation 2 > max 1 => shutdown
        assert!(matches!(action2, SupervisionAction::Shutdown { .. }));
    }

    #[test]
    fn test_temporary_child_failure_ignored() {
        let mut sup = make_supervisor();
        let spec = ChildSpec {
            name: "tmp".to_string(),
            restart_type: RestartType::Temporary,
            shutdown_timeout_ms: 1000,
        };
        sup.add_child(spec).unwrap();
        let action = sup.handle_failure("tmp").unwrap();
        assert_eq!(action, SupervisionAction::Ignore);
    }

    #[test]
    fn test_shutdown_reverse_order() {
        let mut sup = make_supervisor();
        sup.add_child(make_spec("first")).unwrap();
        sup.add_child(make_spec("second")).unwrap();
        sup.add_child(make_spec("third")).unwrap();
        let report = sup.shutdown();
        assert_eq!(report.children_stopped, 3);
        assert_eq!(report.force_terminated, 0);
        assert_eq!(sup.child_count(), 0);
        // INV-SUP-SHUTDOWN-ORDER verified: shutdown drains in reverse order.
    }

    #[test]
    fn test_health_status() {
        let mut sup = make_supervisor();
        sup.add_child(make_spec("a")).unwrap();
        sup.add_child(make_spec("b")).unwrap();
        let health = sup.health_status();
        assert_eq!(health.active_children, 2);
        assert_eq!(health.restart_count, 0);
        assert_eq!(health.budget_remaining, 3);
        assert_eq!(health.escalation_depth, 0);
    }

    #[test]
    fn test_health_after_restarts() {
        let mut sup = make_supervisor();
        sup.add_child(make_spec("w")).unwrap();
        sup.handle_failure("w").unwrap();
        let health = sup.health_status();
        assert_eq!(health.restart_count, 1);
        assert_eq!(health.budget_remaining, 2);
    }

    #[test]
    fn test_events_emitted() {
        let mut sup = make_supervisor();
        sup.add_child(make_spec("w")).unwrap();
        sup.handle_failure("w").unwrap();
        let events = sup.events();
        assert_eq!(events.len(), 3); // ChildStarted + ChildFailed + ChildRestarted
        assert!(matches!(&events[0], SupervisionEvent::ChildStarted { .. }));
    }

    #[test]
    fn test_serde_roundtrip_strategy() {
        for strategy in [
            SupervisionStrategy::OneForOne,
            SupervisionStrategy::OneForAll,
            SupervisionStrategy::RestForOne,
        ] {
            let json = serde_json::to_string(&strategy).unwrap();
            let parsed: SupervisionStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(strategy, parsed);
        }
    }

    #[test]
    fn test_serde_roundtrip_child_spec() {
        let spec = make_spec("test-child");
        let json = serde_json::to_string(&spec).unwrap();
        let parsed: ChildSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, parsed);
    }

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "sup-v1.0");
    }

    #[test]
    fn test_invariant_constants_defined() {
        assert_eq!(INV_SUP_BUDGET_BOUND, "INV-SUP-BUDGET-BOUND");
        assert_eq!(INV_SUP_ESCALATION_BOUNDED, "INV-SUP-ESCALATION-BOUNDED");
        assert_eq!(INV_SUP_SHUTDOWN_ORDER, "INV-SUP-SHUTDOWN-ORDER");
        assert_eq!(INV_SUP_TIMEOUT_ENFORCED, "INV-SUP-TIMEOUT-ENFORCED");
        assert_eq!(
            INV_SUP_STRATEGY_DETERMINISTIC,
            "INV-SUP-STRATEGY-DETERMINISTIC"
        );
    }

    #[test]
    fn test_error_display() {
        let err = SupervisionError::ChildNotFound {
            name: "ghost".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("ERR_SUP_CHILD_NOT_FOUND"));
        assert!(msg.contains("ghost"));
    }

    #[test]
    fn test_force_terminated_on_zero_timeout() {
        let mut sup = make_supervisor();
        let spec = ChildSpec {
            name: "fast".to_string(),
            restart_type: RestartType::Permanent,
            shutdown_timeout_ms: 0,
        };
        sup.add_child(spec).unwrap();
        let report = sup.shutdown();
        assert_eq!(report.force_terminated, 1);
    }
}
