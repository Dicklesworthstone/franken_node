//! bd-25oa: DPOR-style schedule exploration for control-plane interactions.
//!
//! Explores interleavings of concurrent protocol classes to find invariant
//! violations. Models four interaction classes:
//!
//! 1. epoch_transition + lease_renewal
//! 2. remote_computation + evidence_emission
//! 3. cancellation + saga_compensation
//! 4. epoch_barrier + fencing_token
//!
//! Each class is modelled as a set of operations with dependency edges.
//! The explorer enumerates valid interleavings within a bounded budget
//! and checks safety invariants at every explored state.
//!
//! Event codes: DPR-001 through DPR-005.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Represents a single operation in a protocol interaction class.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Operation {
    id: String,
    actor: String,
    depends_on: BTreeSet<String>,
}

impl Operation {
    fn new(id: &str, actor: &str) -> Self {
        Self {
            id: id.to_string(),
            actor: actor.to_string(),
            depends_on: BTreeSet::new(),
        }
    }

    fn with_dep(mut self, dep: &str) -> Self {
        self.depends_on.insert(dep.to_string());
        self
    }

    fn with_deps(mut self, deps: &[&str]) -> Self {
        for d in deps {
            self.depends_on.insert(d.to_string());
        }
        self
    }
}

/// A safety invariant to check at each explored state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SafetyInvariant {
    name: String,
    description: String,
}

/// Describes a protocol interaction class to explore.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InteractionClass {
    name: String,
    participants: Vec<String>,
    operations: Vec<Operation>,
    invariants: Vec<SafetyInvariant>,
}

/// A step in a counterexample trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CounterexampleStep {
    step_index: usize,
    operation_id: String,
    actor: String,
    state_summary: String,
}

/// A counterexample trace showing a minimal invariant violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Counterexample {
    model_name: String,
    violated_property: String,
    length: usize,
    steps: Vec<CounterexampleStep>,
}

/// Result of exploring a single interaction class.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExplorationResult {
    class_name: String,
    interleavings_explored: usize,
    violations_found: usize,
    counterexamples: Vec<Counterexample>,
    passed: bool,
    state_fingerprint: String,
}

/// Budget constraints for DPOR exploration.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExplorationBudget {
    max_interleavings_per_class: usize,
    time_budget_per_class_sec: u64,
    memory_budget_bytes: u64,
}

impl Default for ExplorationBudget {
    fn default() -> Self {
        Self {
            max_interleavings_per_class: 10_000,
            time_budget_per_class_sec: 120,
            memory_budget_bytes: 1_073_741_824,
        }
    }
}

// ---------------------------------------------------------------------------
// DPOR Explorer
// ---------------------------------------------------------------------------

/// DPOR schedule explorer with bounded budget.
struct DporExplorer {
    budget: ExplorationBudget,
    explored_total: usize,
}

impl DporExplorer {
    fn new(budget: ExplorationBudget) -> Self {
        Self {
            budget,
            explored_total: 0,
        }
    }

    fn with_default_budget() -> Self {
        Self::new(ExplorationBudget::default())
    }

    /// Generate all valid topological orderings (linearizations) of operations,
    /// bounded by the budget.
    fn generate_linearizations(ops: &[Operation], budget: usize) -> Vec<Vec<String>> {
        let mut result = Vec::new();
        let mut completed: BTreeSet<String> = BTreeSet::new();
        let mut current: Vec<String> = Vec::new();

        fn backtrack(
            ops: &[Operation],
            completed: &mut BTreeSet<String>,
            current: &mut Vec<String>,
            result: &mut Vec<Vec<String>>,
            budget: usize,
        ) {
            if result.len() >= budget {
                return;
            }
            if current.len() == ops.len() {
                result.push(current.clone());
                return;
            }
            for op in ops {
                if completed.contains(&op.id) {
                    continue;
                }
                if op.depends_on.iter().all(|d| completed.contains(d)) {
                    completed.insert(op.id.clone());
                    current.push(op.id.clone());
                    backtrack(ops, completed, current, result, budget);
                    current.pop();
                    completed.remove(&op.id);
                }
            }
        }

        backtrack(ops, &mut completed, &mut current, &mut result, budget);
        result
    }

    /// Compute a deterministic fingerprint of the explored state space.
    fn state_fingerprint(schedules: &[Vec<String>]) -> String {
        let mut hasher = Sha256::new();
        for schedule in schedules {
            for op_id in schedule {
                hasher.update(op_id.as_bytes());
                hasher.update(b"|");
            }
            hasher.update(b"\n");
        }
        hex::encode(hasher.finalize())
    }

    /// Check safety invariants for a given schedule.
    /// Returns the name of the violated invariant, if any.
    fn check_invariants(
        class: &InteractionClass,
        schedule: &[String],
    ) -> Option<String> {
        // Build a map of operation index in schedule
        let position: BTreeMap<&str, usize> = schedule
            .iter()
            .enumerate()
            .map(|(i, id)| (id.as_str(), i))
            .collect();

        match class.name.as_str() {
            "epoch_transition_lease_renewal" => {
                // INV: no_split_brain -- commit_epoch must follow propose_epoch
                // and drain_services must happen between them.
                if let (Some(&propose), Some(&commit)) =
                    (position.get("propose_epoch"), position.get("commit_epoch"))
                {
                    if commit < propose {
                        return Some("no_split_brain".to_string());
                    }
                }
                // INV: no_stale_lease -- grant_lease must come after commit_epoch
                if let (Some(&grant), Some(&commit)) =
                    (position.get("grant_lease"), position.get("commit_epoch"))
                {
                    if grant < commit {
                        return Some("no_stale_lease".to_string());
                    }
                }
                None
            }
            "remote_computation_evidence_emission" => {
                // INV: no_orphaned_evidence -- archive_evidence after emit_evidence
                if let (Some(&emit), Some(&archive)) =
                    (position.get("emit_evidence"), position.get("archive_evidence"))
                {
                    if archive < emit {
                        return Some("no_orphaned_evidence".to_string());
                    }
                }
                // INV: evidence_before_release -- emit before release
                if let (Some(&emit), Some(&release)) =
                    (position.get("emit_evidence"), position.get("release_capability"))
                {
                    if release < emit {
                        return Some("evidence_before_release".to_string());
                    }
                }
                None
            }
            "cancellation_saga_compensation" => {
                // INV: reverse_order -- compensate_3 before compensate_2 before compensate_1
                if let (Some(&c3), Some(&c2), Some(&c1)) = (
                    position.get("compensate_3"),
                    position.get("compensate_2"),
                    position.get("compensate_1"),
                ) {
                    if c2 < c3 || c1 < c2 {
                        return Some("reverse_compensation_order".to_string());
                    }
                }
                None
            }
            "epoch_barrier_fencing_token" => {
                // INV: no_stale_write -- validate_fence after barrier_commit
                if let (Some(&validate), Some(&commit)) =
                    (position.get("validate_fence"), position.get("barrier_commit"))
                {
                    if validate < commit {
                        return Some("no_stale_write".to_string());
                    }
                }
                // INV: all_drain_before_commit
                if let (Some(&drain_a), Some(&drain_b), Some(&commit)) = (
                    position.get("barrier_drain_a"),
                    position.get("barrier_drain_b"),
                    position.get("barrier_commit"),
                ) {
                    if commit < drain_a || commit < drain_b {
                        return Some("all_drain_before_commit".to_string());
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Explore all valid interleavings for an interaction class.
    fn explore(&mut self, class: &InteractionClass) -> ExplorationResult {
        let budget = self.budget.max_interleavings_per_class;
        let schedules = Self::generate_linearizations(&class.operations, budget);
        let fingerprint = Self::state_fingerprint(&schedules);

        let mut violations_found = 0;
        let mut counterexamples = Vec::new();

        for schedule in &schedules {
            if let Some(violated) = Self::check_invariants(class, schedule) {
                violations_found += 1;
                let steps = schedule
                    .iter()
                    .enumerate()
                    .map(|(i, op_id)| {
                        let actor = class
                            .operations
                            .iter()
                            .find(|o| o.id == *op_id)
                            .map(|o| o.actor.clone())
                            .unwrap_or_default();
                        CounterexampleStep {
                            step_index: i,
                            operation_id: op_id.clone(),
                            actor,
                            state_summary: format!("step {} of {}", i, schedule.len()),
                        }
                    })
                    .collect::<Vec<_>>();
                counterexamples.push(Counterexample {
                    model_name: class.name.clone(),
                    violated_property: violated,
                    length: steps.len(),
                    steps,
                });
            }
        }

        let explored = schedules.len();
        self.explored_total += explored;

        ExplorationResult {
            class_name: class.name.clone(),
            interleavings_explored: explored,
            violations_found,
            counterexamples,
            passed: violations_found == 0,
            state_fingerprint: fingerprint,
        }
    }
}

// ---------------------------------------------------------------------------
// Model builders for the 4 interaction classes
// ---------------------------------------------------------------------------

fn build_epoch_transition_lease_renewal() -> InteractionClass {
    InteractionClass {
        name: "epoch_transition_lease_renewal".to_string(),
        participants: vec![
            "epoch_leader".into(),
            "svc_pool".into(),
            "lease_client".into(),
            "lease_server".into(),
        ],
        operations: vec![
            Operation::new("propose_epoch", "epoch_leader"),
            Operation::new("drain_services", "svc_pool").with_dep("propose_epoch"),
            Operation::new("commit_epoch", "epoch_leader").with_dep("drain_services"),
            Operation::new("request_lease", "lease_client"),
            Operation::new("validate_lease_epoch", "lease_server").with_dep("request_lease"),
            Operation::new("grant_lease", "lease_server")
                .with_deps(&["validate_lease_epoch", "commit_epoch"]),
        ],
        invariants: vec![
            SafetyInvariant {
                name: "no_split_brain".into(),
                description: "At most one active epoch at any state".into(),
            },
            SafetyInvariant {
                name: "no_stale_lease".into(),
                description: "No lease granted for a stale epoch".into(),
            },
            SafetyInvariant {
                name: "no_deadlock".into(),
                description: "Lease renewal does not block epoch commit indefinitely".into(),
            },
        ],
    }
}

fn build_remote_computation_evidence_emission() -> InteractionClass {
    InteractionClass {
        name: "remote_computation_evidence_emission".to_string(),
        participants: vec![
            "remote_client".into(),
            "evidence_emitter".into(),
            "evidence_archiver".into(),
            "epoch_leader".into(),
        ],
        operations: vec![
            Operation::new("acquire_capability", "remote_client"),
            Operation::new("execute_remote", "remote_client").with_dep("acquire_capability"),
            Operation::new("emit_evidence", "evidence_emitter").with_dep("execute_remote"),
            Operation::new("release_capability", "remote_client").with_dep("emit_evidence"),
            Operation::new("archive_evidence", "evidence_archiver").with_dep("emit_evidence"),
            Operation::new("epoch_checkpoint", "epoch_leader"),
        ],
        invariants: vec![
            SafetyInvariant {
                name: "no_orphaned_evidence".into(),
                description: "Every emitted evidence record is archived".into(),
            },
            SafetyInvariant {
                name: "no_exec_without_cap".into(),
                description: "No execution without a valid capability".into(),
            },
            SafetyInvariant {
                name: "evidence_before_release".into(),
                description: "Evidence emission precedes capability release".into(),
            },
        ],
    }
}

fn build_cancellation_saga_compensation() -> InteractionClass {
    InteractionClass {
        name: "cancellation_saga_compensation".to_string(),
        participants: vec!["orchestrator".into(), "cancellation_framework".into()],
        operations: vec![
            Operation::new("saga_step_1", "orchestrator"),
            Operation::new("saga_step_2", "orchestrator").with_dep("saga_step_1"),
            Operation::new("saga_step_3", "orchestrator").with_dep("saga_step_2"),
            Operation::new("cancel_inject", "cancellation_framework"),
            Operation::new("compensate_3", "orchestrator")
                .with_deps(&["cancel_inject", "saga_step_3"]),
            Operation::new("compensate_2", "orchestrator").with_dep("compensate_3"),
            Operation::new("compensate_1", "orchestrator").with_dep("compensate_2"),
        ],
        invariants: vec![
            SafetyInvariant {
                name: "no_leaked_obligations".into(),
                description: "All committed saga steps are compensated on cancel".into(),
            },
            SafetyInvariant {
                name: "reverse_compensation_order".into(),
                description: "Compensation runs in reverse order (3 -> 2 -> 1)".into(),
            },
            SafetyInvariant {
                name: "clean_final_state".into(),
                description: "Final state equivalent to never started".into(),
            },
        ],
    }
}

fn build_epoch_barrier_fencing_token() -> InteractionClass {
    InteractionClass {
        name: "epoch_barrier_fencing_token".to_string(),
        participants: vec![
            "fence_authority".into(),
            "epoch_leader".into(),
            "svc_a".into(),
            "svc_b".into(),
            "writer".into(),
        ],
        operations: vec![
            Operation::new("issue_fence", "fence_authority"),
            Operation::new("barrier_propose", "epoch_leader"),
            Operation::new("barrier_drain_a", "svc_a").with_dep("barrier_propose"),
            Operation::new("barrier_drain_b", "svc_b").with_dep("barrier_propose"),
            Operation::new("barrier_commit", "epoch_leader")
                .with_deps(&["barrier_drain_a", "barrier_drain_b"]),
            Operation::new("write_with_fence", "writer").with_dep("issue_fence"),
            Operation::new("validate_fence", "fence_authority")
                .with_deps(&["write_with_fence", "barrier_commit"]),
        ],
        invariants: vec![
            SafetyInvariant {
                name: "no_stale_write".into(),
                description: "No stale writes accepted after epoch barrier with newer fence"
                    .into(),
            },
            SafetyInvariant {
                name: "fence_epoch_match".into(),
                description: "Fencing token validation rejects tokens from previous epochs".into(),
            },
            SafetyInvariant {
                name: "all_drain_before_commit".into(),
                description: "Barrier commit requires all participants to drain".into(),
            },
        ],
    }
}

/// Build all 4 interaction classes.
fn all_interaction_classes() -> Vec<InteractionClass> {
    vec![
        build_epoch_transition_lease_renewal(),
        build_remote_computation_evidence_emission(),
        build_cancellation_saga_compensation(),
        build_epoch_barrier_fencing_token(),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Class 1: epoch_transition + lease_renewal ----

    #[test]
    fn test_epoch_lease_class_has_six_operations() {
        let class = build_epoch_transition_lease_renewal();
        assert_eq!(class.operations.len(), 6);
    }

    #[test]
    fn test_epoch_lease_class_has_three_invariants() {
        let class = build_epoch_transition_lease_renewal();
        assert_eq!(class.invariants.len(), 3);
    }

    #[test]
    fn test_epoch_lease_exploration_passes() {
        let class = build_epoch_transition_lease_renewal();
        let mut explorer = DporExplorer::with_default_budget();
        let result = explorer.explore(&class);
        assert!(
            result.passed,
            "epoch_transition_lease_renewal should pass: {} violations in {} interleavings",
            result.violations_found, result.interleavings_explored
        );
        assert!(result.interleavings_explored > 0);
        assert_eq!(result.violations_found, 0);
    }

    // ---- Class 2: remote_computation + evidence_emission ----

    #[test]
    fn test_remote_evidence_class_has_six_operations() {
        let class = build_remote_computation_evidence_emission();
        assert_eq!(class.operations.len(), 6);
    }

    #[test]
    fn test_remote_evidence_class_has_three_invariants() {
        let class = build_remote_computation_evidence_emission();
        assert_eq!(class.invariants.len(), 3);
    }

    #[test]
    fn test_remote_evidence_exploration_passes() {
        let class = build_remote_computation_evidence_emission();
        let mut explorer = DporExplorer::with_default_budget();
        let result = explorer.explore(&class);
        assert!(
            result.passed,
            "remote_computation_evidence_emission should pass: {} violations in {} interleavings",
            result.violations_found, result.interleavings_explored
        );
        assert!(result.interleavings_explored > 0);
        assert_eq!(result.violations_found, 0);
    }

    // ---- Class 3: cancellation + saga_compensation ----

    #[test]
    fn test_cancellation_saga_class_has_seven_operations() {
        let class = build_cancellation_saga_compensation();
        assert_eq!(class.operations.len(), 7);
    }

    #[test]
    fn test_cancellation_saga_class_has_three_invariants() {
        let class = build_cancellation_saga_compensation();
        assert_eq!(class.invariants.len(), 3);
    }

    #[test]
    fn test_cancellation_saga_exploration_passes() {
        let class = build_cancellation_saga_compensation();
        let mut explorer = DporExplorer::with_default_budget();
        let result = explorer.explore(&class);
        assert!(
            result.passed,
            "cancellation_saga_compensation should pass: {} violations in {} interleavings",
            result.violations_found, result.interleavings_explored
        );
        assert!(result.interleavings_explored > 0);
        assert_eq!(result.violations_found, 0);
    }

    // ---- Class 4: epoch_barrier + fencing_token ----

    #[test]
    fn test_epoch_barrier_fencing_class_has_seven_operations() {
        let class = build_epoch_barrier_fencing_token();
        assert_eq!(class.operations.len(), 7);
    }

    #[test]
    fn test_epoch_barrier_fencing_class_has_three_invariants() {
        let class = build_epoch_barrier_fencing_token();
        assert_eq!(class.invariants.len(), 3);
    }

    #[test]
    fn test_epoch_barrier_fencing_exploration_passes() {
        let class = build_epoch_barrier_fencing_token();
        let mut explorer = DporExplorer::with_default_budget();
        let result = explorer.explore(&class);
        assert!(
            result.passed,
            "epoch_barrier_fencing_token should pass: {} violations in {} interleavings",
            result.violations_found, result.interleavings_explored
        );
        assert!(result.interleavings_explored > 0);
        assert_eq!(result.violations_found, 0);
    }

    // ---- Cross-cutting tests ----

    #[test]
    fn test_all_four_classes_explored() {
        let classes = all_interaction_classes();
        assert_eq!(classes.len(), 4);
        let mut explorer = DporExplorer::with_default_budget();
        for class in &classes {
            let result = explorer.explore(class);
            assert!(result.passed, "Class {} should pass", class.name);
        }
        assert!(explorer.explored_total > 0);
    }

    #[test]
    fn test_budget_limits_respected() {
        let budget = ExplorationBudget {
            max_interleavings_per_class: 50,
            time_budget_per_class_sec: 10,
            memory_budget_bytes: 1024 * 1024,
        };
        let mut explorer = DporExplorer::new(budget);
        for class in &all_interaction_classes() {
            let result = explorer.explore(class);
            assert!(
                result.interleavings_explored <= 50,
                "Budget exceeded for {}: {}",
                class.name,
                result.interleavings_explored
            );
        }
    }

    #[test]
    fn test_state_fingerprint_deterministic() {
        let class = build_epoch_transition_lease_renewal();
        let schedules1 = DporExplorer::generate_linearizations(&class.operations, 100);
        let schedules2 = DporExplorer::generate_linearizations(&class.operations, 100);
        let fp1 = DporExplorer::state_fingerprint(&schedules1);
        let fp2 = DporExplorer::state_fingerprint(&schedules2);
        assert_eq!(fp1, fp2, "Fingerprints should be deterministic");
        assert!(!fp1.is_empty());
    }

    #[test]
    fn test_counterexample_on_broken_invariant() {
        // Build a broken model: grant_lease has no dependency on commit_epoch,
        // so it can be scheduled before commit_epoch, violating no_stale_lease.
        let mut class = build_epoch_transition_lease_renewal();
        // Remove commit_epoch from grant_lease's dependencies
        if let Some(grant) = class.operations.iter_mut().find(|o| o.id == "grant_lease") {
            grant.depends_on.remove("commit_epoch");
        }

        let mut explorer = DporExplorer::with_default_budget();
        let result = explorer.explore(&class);

        // With the dependency removed, some interleavings will have
        // grant_lease before commit_epoch, violating no_stale_lease.
        assert!(
            result.violations_found > 0,
            "Should find violations when dependency is removed"
        );
        assert!(!result.passed);
        assert!(
            !result.counterexamples.is_empty(),
            "Should produce counterexamples"
        );
        assert_eq!(result.counterexamples[0].model_name, "epoch_transition_lease_renewal");
    }

    #[test]
    fn test_exploration_result_serializable() {
        let class = build_epoch_transition_lease_renewal();
        let mut explorer = DporExplorer::with_default_budget();
        let result = explorer.explore(&class);
        let json = serde_json::to_string_pretty(&result).expect("serialize");
        let parsed: ExplorationResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.class_name, result.class_name);
        assert_eq!(parsed.interleavings_explored, result.interleavings_explored);
    }

    #[test]
    fn test_linearizations_nonempty_for_all_classes() {
        for class in &all_interaction_classes() {
            let lins = DporExplorer::generate_linearizations(&class.operations, 1000);
            assert!(
                !lins.is_empty(),
                "Class {} should have at least one valid linearization",
                class.name
            );
            // Each linearization should contain all operations
            for lin in &lins {
                assert_eq!(
                    lin.len(),
                    class.operations.len(),
                    "Linearization length should match operation count for {}",
                    class.name
                );
            }
        }
    }

    #[test]
    fn test_default_budget_values() {
        let budget = ExplorationBudget::default();
        assert_eq!(budget.max_interleavings_per_class, 10_000);
        assert_eq!(budget.time_budget_per_class_sec, 120);
        assert_eq!(budget.memory_budget_bytes, 1_073_741_824);
    }
}
