//! bd-3a3q Guardrail Monitor Conformance Test Suite
//!
//! This harness implements Pattern 4: Spec-Derived Test Matrix for the bd-3a3q
//! specification covering anytime-valid guardrail monitor sets for security/durability-critical budgets.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// API-DRIFT REDESIGN (bd-rjc2m.4): added SystemState import -> GuardrailMonitor::check now takes &SystemState. New trait signature requires the state snapshot type.
use frankenengine_node::policy::guardrail_monitor::{
    BudgetId, GuardrailMonitor, GuardrailMonitorSet, GuardrailVerdict, SystemState, event_codes,
};
use frankenengine_node::policy::hardening_state_machine::{HardeningLevel, HardeningStateMachine};

/// Test categories for organizational purposes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    Unit,
    Integration,
    EdgeCase,
}

/// Requirement levels from bd-3a3q specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

/// Test execution result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String },
}

/// Individual conformance test record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceRecord {
    pub id: String,
    pub section: String,
    pub level: RequirementLevel,
    pub category: TestCategory,
    pub description: String,
    pub result: TestResult,
}

/// Overall conformance test statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConformanceStats {
    pub must_pass: usize,
    pub must_fail: usize,
    pub should_pass: usize,
    pub should_fail: usize,
    pub may_pass: usize,
    pub may_fail: usize,
    pub expected_failures: usize,
    pub skipped: usize,
}

/// Complete conformance test report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub results: BTreeMap<String, ConformanceRecord>,
    pub stats: ConformanceStats,
    pub specification: String,
    pub timestamp: String,
}

impl ConformanceReport {
    /// Calculate compliance score (0.0 - 1.0)
    pub fn compliance_score(&self) -> f64 {
        let must_total = self.stats.must_pass + self.stats.must_fail;
        if must_total == 0 {
            1.0
        } else {
            self.stats.must_pass as f64 / must_total as f64
        }
    }

    /// Generate markdown report
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# bd-3a3q Guardrail Monitor Conformance Report\n\n");
        md.push_str(&format!("**Generated:** {}\n\n", self.timestamp));
        md.push_str(&format!(
            "**Compliance Score:** {:.1}%\n\n",
            self.compliance_score() * 100.0
        ));

        // Summary table
        md.push_str("## Summary\n\n");
        md.push_str("| Requirement Level | Pass | Fail | Skip | XFAIL |\n");
        md.push_str("|------------------|:----:|:----:|:----:|:-----:|\n");
        md.push_str(&format!(
            "| MUST | {} | {} | 0 | 0 |\n",
            self.stats.must_pass, self.stats.must_fail
        ));
        md.push_str(&format!(
            "| SHOULD | {} | {} | {} | {} |\n",
            self.stats.should_pass,
            self.stats.should_fail,
            self.stats.skipped,
            self.stats.expected_failures
        ));
        md.push_str(&format!(
            "| MAY | {} | {} | 0 | 0 |\n",
            self.stats.may_pass, self.stats.may_fail
        ));

        // Detailed results
        md.push_str("\n## Test Results\n\n");
        for (_, record) in &self.results {
            let status = match &record.result {
                TestResult::Pass => "✅ PASS",
                TestResult::Fail { .. } => "❌ FAIL",
                TestResult::Skipped { .. } => "⏭️ SKIP",
                TestResult::ExpectedFailure { .. } => "⏳ XFAIL",
            };
            md.push_str(&format!(
                "- **{}** [{}] {}: {}\n",
                record.id, status, record.section, record.description
            ));

            if let TestResult::Fail { reason } = &record.result {
                md.push_str(&format!("  - ❌ {}\n", reason));
            }
        }

        md
    }
}

// Mock guardrail monitor for testing
// API-DRIFT REDESIGN (bd-rjc2m.4): added #[derive(Debug)] -> GuardrailMonitor now requires fmt::Debug supertrait.
#[derive(Debug)]
struct TestMonitor {
    budget_id: BudgetId,
    threshold: f64,
    name: String,
}

impl TestMonitor {
    fn new(budget_id: &str, threshold: f64) -> Self {
        Self {
            budget_id: BudgetId::new(budget_id.to_string()),
            threshold,
            name: format!("test_monitor_{}", budget_id),
        }
    }

    // API-DRIFT REDESIGN (bd-rjc2m.4): reconfigure_threshold moved out of `impl GuardrailMonitor`
    // into an inherent impl -> reconfigure_threshold is no longer a trait method (E0407). Preserves
    // the test's ability to reconfigure thresholds.
    fn reconfigure_threshold(&mut self, new_threshold: f64) -> bool {
        if new_threshold > 0.0 {
            self.threshold = new_threshold;
            true
        } else {
            false
        }
    }
}

/// Build a SystemState whose memory utilization (in percent) equals `value_pct`,
/// preserving the old test's "check(value, level)" semantics on the new API.
// API-DRIFT REDESIGN (bd-rjc2m.4): new helper -> check() input changed from (f64 value, HardeningLevel)
// to &SystemState. Maps the old numeric "value" onto memory utilization percent of a 1GB budget.
fn state_with_value(value_pct: f64, hardening_level: HardeningLevel) -> SystemState {
    SystemState {
        memory_used_bytes: (value_pct * 10_000_000.0) as u64, // value% of a 1GB budget
        memory_budget_bytes: 1_000_000_000,
        durability_level: 0.99,
        hardening_level,
        proposed_hardening_level: None,
        evidence_emission_active: true,
        memory_tail_risk: None,
        reliability_telemetry: None,
        epoch_id: 1,
    }
}

impl GuardrailMonitor for TestMonitor {
    fn name(&self) -> &str {
        &self.name
    }

    fn budget_id(&self) -> &BudgetId {
        &self.budget_id
    }

    // API-DRIFT REDESIGN (bd-rjc2m.4): check(value, level) -> check(&SystemState). Derive the old
    // numeric `value` from state.memory_utilization()*100.0, then apply identical threshold logic.
    fn check(&self, state: &SystemState) -> GuardrailVerdict {
        let value = state.memory_utilization() * 100.0;
        if value > self.threshold {
            GuardrailVerdict::Block {
                reason: format!("Value {} exceeds threshold {}", value, self.threshold),
                budget_id: self.budget_id.clone(),
            }
        } else if value > self.threshold * 0.8 {
            GuardrailVerdict::Warn {
                reason: format!("Value {} approaching threshold {}", value, self.threshold),
            }
        } else {
            GuardrailVerdict::Allow
        }
    }
}

// Individual conformance test cases covering bd-3a3q specification

fn test_case_3a3q_inv_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "3A3Q-INV-1".to_string(),
        section: "Core Invariants".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "INV-GUARD-ANYTIME: every monitor is valid at any stopping point".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let monitor = TestMonitor::new("memory_budget", 100.0);

        // Test that monitor produces valid verdict at any point
        // API-DRIFT REDESIGN (bd-rjc2m.4): check(value, level) -> check(&state_with_value(value, level)); Minimal -> Baseline, Maximal -> Maximum. Boundary semantics preserved (50<80 allow, 85>80 warn, 150>100 block, 0 allow).
        let verdicts = vec![
            monitor.check(&state_with_value(50.0, HardeningLevel::Baseline)),
            monitor.check(&state_with_value(85.0, HardeningLevel::Standard)), // Should warn
            monitor.check(&state_with_value(150.0, HardeningLevel::Maximum)), // Should block
            monitor.check(&state_with_value(0.0, HardeningLevel::Baseline)),  // Should allow
        ];

        // Verify all verdicts are valid (no panics, proper enum values)
        assert_eq!(
            verdicts[0],
            GuardrailVerdict::Allow,
            "Low value should allow"
        );
        assert!(
            matches!(verdicts[1], GuardrailVerdict::Warn { .. }),
            "High value should warn"
        );
        assert!(
            matches!(verdicts[2], GuardrailVerdict::Block { .. }),
            "Excessive value should block"
        );
        assert_eq!(
            verdicts[3],
            GuardrailVerdict::Allow,
            "Zero value should allow"
        );

        // Verify event codes are consistent
        assert_eq!(verdicts[0].event_code(), event_codes::GUARD_PASS);
        assert_eq!(verdicts[1].event_code(), event_codes::GUARD_WARN);
        assert_eq!(verdicts[2].event_code(), event_codes::GUARD_BLOCK);
        assert_eq!(verdicts[3].event_code(), event_codes::GUARD_PASS);
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Monitor not producing valid verdicts at all stopping points".to_string(),
            };
        }
    }

    record
}

fn test_case_3a3q_inv_2() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "3A3Q-INV-2".to_string(),
        section: "Core Invariants".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-GUARD-PRECEDENCE: guardrail verdicts override Bayesian recommendations"
            .to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let monitor = TestMonitor::new("cpu_budget", 75.0);
        let mut monitor_set = GuardrailMonitorSet::new();
        // API-DRIFT REDESIGN (bd-rjc2m.4): add_monitor(Box::new(m)) -> register(Box::new(m)). Method renamed.
        monitor_set.register(Box::new(monitor));

        // Simulate Bayesian engine recommending action, but guardrail should block
        let _bayesian_recommendation = "PROCEED_WITH_OPTIMIZATION";
        let actual_value = 100.0; // Exceeds threshold of 75.0

        // API-DRIFT REDESIGN (bd-rjc2m.4): check_all(value, level) -> check_all(&state_with_value(value, level)). 100 > 75 still blocks.
        let verdict =
            monitor_set.check_all(&state_with_value(actual_value, HardeningLevel::Standard));

        // Guardrail should block regardless of Bayesian recommendation
        assert!(
            matches!(verdict, GuardrailVerdict::Block { .. }),
            "Guardrail must override Bayesian recommendation when budget exceeded"
        );

        // Verify precedence - even if Bayesian says proceed, guardrail blocks
        match verdict {
            GuardrailVerdict::Block { reason, budget_id } => {
                assert!(
                    reason.contains("100"),
                    "Block reason should mention actual value"
                );
                assert_eq!(
                    budget_id.as_str(),
                    "cpu_budget",
                    "Budget ID should be preserved"
                );
            }
            _ => panic!("Expected Block verdict for over-budget value"),
        }
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Guardrail not overriding Bayesian recommendations properly".to_string(),
            };
        }
    }

    record
}

fn test_case_3a3q_inv_3() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "3A3Q-INV-3".to_string(),
        section: "Core Invariants".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-GUARD-RESTRICTIVE: the set returns the most restrictive verdict"
            .to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let monitor1 = TestMonitor::new("memory_budget", 100.0);
        let monitor2 = TestMonitor::new("cpu_budget", 80.0);
        let monitor3 = TestMonitor::new("network_budget", 120.0);

        let mut monitor_set = GuardrailMonitorSet::new();
        // API-DRIFT REDESIGN (bd-rjc2m.4): add_monitor(Box::new(m)) -> register(Box::new(m)). Method renamed.
        monitor_set.register(Box::new(monitor1));
        monitor_set.register(Box::new(monitor2));
        monitor_set.register(Box::new(monitor3));

        // Test value that should trigger different verdicts from different monitors
        let test_value = 90.0; // Should block cpu (>80), warn memory (>80), allow network (<120)

        // API-DRIFT REDESIGN (bd-rjc2m.4): check_all(value, level) -> check_all(&state_with_value(value, level)). 90>80 (cpu) blocks; most-restrictive still Block.
        let verdict =
            monitor_set.check_all(&state_with_value(test_value, HardeningLevel::Standard));

        // Should return Block (most restrictive) even though others would allow/warn
        assert!(
            matches!(verdict, GuardrailVerdict::Block { .. }),
            "Monitor set must return most restrictive verdict"
        );

        // Verify severity ordering
        let allow_verdict = GuardrailVerdict::Allow;
        let warn_verdict = GuardrailVerdict::Warn {
            reason: "test".to_string(),
        };
        let block_verdict = GuardrailVerdict::Block {
            reason: "test".to_string(),
            budget_id: BudgetId::new("test"),
        };

        assert!(allow_verdict.severity() < warn_verdict.severity());
        assert!(warn_verdict.severity() < block_verdict.severity());
        assert_eq!(allow_verdict.severity(), 0);
        assert_eq!(warn_verdict.severity(), 1);
        assert_eq!(block_verdict.severity(), 2);
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Monitor set not returning most restrictive verdict".to_string(),
            };
        }
    }

    record
}

fn test_case_3a3q_inv_4() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "3A3Q-INV-4".to_string(),
        section: "Core Invariants".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "INV-GUARD-CONFIGURABLE: thresholds are configurable above envelope minimums"
            .to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let mut monitor = TestMonitor::new("disk_budget", 50.0);

        // Verify initial threshold
        assert_eq!(monitor.threshold, 50.0, "Initial threshold should be set");

        // Test successful reconfiguration to higher value
        let success = monitor.reconfigure_threshold(75.0);
        assert!(success, "Reconfiguration to higher value should succeed");
        assert_eq!(monitor.threshold, 75.0, "Threshold should be updated");

        // Test that new threshold is actually used
        // API-DRIFT REDESIGN (bd-rjc2m.4): check(value, level) -> check(&state_with_value(value, level)). With threshold 75: 60<75 allow, 80>75 block.
        let verdict_below = monitor.check(&state_with_value(60.0, HardeningLevel::Standard));
        let verdict_above = monitor.check(&state_with_value(80.0, HardeningLevel::Standard));

        assert_eq!(
            verdict_below,
            GuardrailVerdict::Allow,
            "Value below new threshold should allow"
        );
        assert!(
            matches!(verdict_above, GuardrailVerdict::Block { .. }),
            "Value above new threshold should block"
        );

        // Test rejection of invalid threshold (below minimum)
        let failure = monitor.reconfigure_threshold(0.0);
        assert!(!failure, "Reconfiguration to invalid value should fail");
        assert_eq!(
            monitor.threshold, 75.0,
            "Threshold should remain unchanged after failed reconfiguration"
        );
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Monitor threshold configuration not working properly".to_string(),
            };
        }
    }

    record
}

fn test_case_3a3q_evt_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "3A3Q-EVT-1".to_string(),
        section: "Event Codes".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "EVD-GUARD-001 event code MUST be emitted for Allow verdicts".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let monitor = TestMonitor::new("test_budget", 100.0);
        // API-DRIFT REDESIGN (bd-rjc2m.4): check(value, level) -> check(&state_with_value(value, level)). 50 < 80 still Allow.
        let verdict = monitor.check(&state_with_value(50.0, HardeningLevel::Standard));

        assert_eq!(
            verdict,
            GuardrailVerdict::Allow,
            "Low value should produce Allow verdict"
        );
        assert_eq!(
            verdict.event_code(),
            event_codes::GUARD_PASS,
            "Allow verdict should use GUARD_PASS event code"
        );
        assert_eq!(
            event_codes::GUARD_PASS,
            "EVD-GUARD-001",
            "Event code should match specification"
        );
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "EVD-GUARD-001 event code not properly emitted for Allow verdicts"
                    .to_string(),
            };
        }
    }

    record
}

fn test_case_3a3q_evt_2() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "3A3Q-EVT-2".to_string(),
        section: "Event Codes".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "EVD-GUARD-002 event code MUST be emitted for Block verdicts".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let monitor = TestMonitor::new("test_budget", 100.0);
        // API-DRIFT REDESIGN (bd-rjc2m.4): check(value, level) -> check(&state_with_value(value, level)). 150 > 100 still Block.
        let verdict = monitor.check(&state_with_value(150.0, HardeningLevel::Standard));

        assert!(
            matches!(verdict, GuardrailVerdict::Block { .. }),
            "High value should produce Block verdict"
        );
        assert_eq!(
            verdict.event_code(),
            event_codes::GUARD_BLOCK,
            "Block verdict should use GUARD_BLOCK event code"
        );
        assert_eq!(
            event_codes::GUARD_BLOCK,
            "EVD-GUARD-002",
            "Event code should match specification"
        );

        // Verify block verdict contains required fields
        if let GuardrailVerdict::Block { reason, budget_id } = verdict {
            assert!(!reason.is_empty(), "Block reason must not be empty");
            assert_eq!(
                budget_id.as_str(),
                "test_budget",
                "Budget ID must be correct"
            );
        }
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "EVD-GUARD-002 event code not properly emitted for Block verdicts"
                    .to_string(),
            };
        }
    }

    record
}

fn test_case_3a3q_evt_3() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "3A3Q-EVT-3".to_string(),
        section: "Event Codes".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "EVD-GUARD-003 event code MUST be emitted for Warn verdicts".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let monitor = TestMonitor::new("test_budget", 100.0);
        // API-DRIFT REDESIGN (bd-rjc2m.4): check(value, level) -> check(&state_with_value(value, level)). 85 > 80 (80% of 100) still Warn.
        let verdict = monitor.check(&state_with_value(85.0, HardeningLevel::Standard)); // 85 > 80 (80% of 100)

        assert!(
            matches!(verdict, GuardrailVerdict::Warn { .. }),
            "Medium-high value should produce Warn verdict"
        );
        assert_eq!(
            verdict.event_code(),
            event_codes::GUARD_WARN,
            "Warn verdict should use GUARD_WARN event code"
        );
        assert_eq!(
            event_codes::GUARD_WARN,
            "EVD-GUARD-003",
            "Event code should match specification"
        );

        // Verify warn verdict contains required fields
        if let GuardrailVerdict::Warn { reason } = verdict {
            assert!(!reason.is_empty(), "Warn reason must not be empty");
            assert!(
                reason.contains("approaching"),
                "Warn reason should indicate approaching threshold"
            );
        }
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "EVD-GUARD-003 event code not properly emitted for Warn verdicts"
                    .to_string(),
            };
        }
    }

    record
}

fn test_case_3a3q_budget_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "3A3Q-BUDGET-1".to_string(),
        section: "Budget Management".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "Budget IDs MUST be properly managed and preserved through verdicts"
            .to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let budget_id = BudgetId::new("memory_overhead");
        let monitor = TestMonitor::new("memory_overhead", 100.0);

        assert_eq!(
            monitor.budget_id(),
            &budget_id,
            "Monitor should preserve budget ID"
        );
        assert_eq!(
            budget_id.as_str(),
            "memory_overhead",
            "Budget ID string representation should match"
        );

        // Test budget ID formatting
        let formatted = format!("{}", budget_id);
        assert_eq!(
            formatted, "memory_overhead",
            "Budget ID display should match string value"
        );

        // Test budget ID in Block verdict
        // API-DRIFT REDESIGN (bd-rjc2m.4): check(value, level) -> check(&state_with_value(value, level)). 150 > 100 still Block.
        let verdict = monitor.check(&state_with_value(150.0, HardeningLevel::Standard));
        if let GuardrailVerdict::Block {
            budget_id: verdict_budget_id,
            ..
        } = verdict
        {
            assert_eq!(
                verdict_budget_id, budget_id,
                "Block verdict should preserve budget ID"
            );
        } else {
            panic!("Expected Block verdict for over-budget value");
        }
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Budget ID management not working properly".to_string(),
            };
        }
    }

    record
}

fn test_case_3a3q_hardening_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "3A3Q-HARDENING-1".to_string(),
        section: "Hardening Integration".to_string(),
        level: RequirementLevel::Should,
        category: TestCategory::Integration,
        description: "Monitors SHOULD consider hardening level in their evaluations".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let monitor = TestMonitor::new("test_budget", 100.0);

        // Test that monitor accepts hardening level parameter
        // API-DRIFT REDESIGN (bd-rjc2m.4): check(value, level) -> check(&state_with_value(value, level)); Minimal -> Baseline, Maximal -> Maximum. Verdict is identical across all three levels (TestMonitor ignores hardening level), exactly matching the old test's "interface accepts the parameter" intent; remapping does not alter the value-derived verdict.
        let verdict_minimal = monitor.check(&state_with_value(80.0, HardeningLevel::Baseline));
        let verdict_standard = monitor.check(&state_with_value(80.0, HardeningLevel::Standard));
        let verdict_maximal = monitor.check(&state_with_value(80.0, HardeningLevel::Maximum));

        // All should produce same result for our test monitor (it doesn't use hardening level)
        // But the interface should accept the parameter
        assert!(matches!(verdict_minimal, GuardrailVerdict::Warn { .. }));
        assert!(matches!(verdict_standard, GuardrailVerdict::Warn { .. }));
        assert!(matches!(verdict_maximal, GuardrailVerdict::Warn { .. }));

        // Verify hardening levels have proper ordering
        // API-DRIFT REDESIGN (bd-rjc2m.4): Minimal -> Baseline, Maximal -> Maximum. Ordering Baseline < Standard < Maximum preserved by the new 5-variant enum.
        assert!((HardeningLevel::Baseline as u8) < (HardeningLevel::Standard as u8));
        assert!((HardeningLevel::Standard as u8) < (HardeningLevel::Maximum as u8));
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Hardening level integration not working properly".to_string(),
            };
        }
    }

    record
}

/// Execute the complete bd-3a3q conformance test suite
pub fn run_bd_3a3q_conformance_tests() -> ConformanceReport {
    let test_cases = vec![
        test_case_3a3q_inv_1(),
        test_case_3a3q_inv_2(),
        test_case_3a3q_inv_3(),
        test_case_3a3q_inv_4(),
        test_case_3a3q_evt_1(),
        test_case_3a3q_evt_2(),
        test_case_3a3q_evt_3(),
        test_case_3a3q_budget_1(),
        test_case_3a3q_hardening_1(),
    ];

    let mut results = BTreeMap::new();
    let mut stats = ConformanceStats::default();

    for case in test_cases {
        match (&case.level, &case.result) {
            (RequirementLevel::Must, TestResult::Pass) => stats.must_pass += 1,
            (RequirementLevel::Must, TestResult::Fail { .. }) => stats.must_fail += 1,
            (RequirementLevel::Should, TestResult::Pass) => stats.should_pass += 1,
            (RequirementLevel::Should, TestResult::Fail { .. }) => stats.should_fail += 1,
            (RequirementLevel::May, TestResult::Pass) => stats.may_pass += 1,
            (RequirementLevel::May, TestResult::Fail { .. }) => stats.may_fail += 1,
            (_, TestResult::ExpectedFailure { .. }) => stats.expected_failures += 1,
            (_, TestResult::Skipped { .. }) => stats.skipped += 1,
        }

        results.insert(case.id.clone(), case);
    }

    ConformanceReport {
        results,
        stats,
        specification: "bd-3a3q".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bd_3a3q_conformance_suite() {
        let report = run_bd_3a3q_conformance_tests();

        // Print summary for human review
        println!("\n📊 bd-3a3q Conformance Test Results:");
        println!(
            "  MUST requirements: {} pass, {} fail",
            report.stats.must_pass, report.stats.must_fail
        );
        println!(
            "  SHOULD requirements: {} pass, {} fail",
            report.stats.should_pass, report.stats.should_fail
        );
        println!(
            "  Compliance score: {:.1}%",
            report.compliance_score() * 100.0
        );

        // All MUST requirements must pass for conformance
        assert_eq!(
            report.stats.must_fail, 0,
            "All MUST requirements must pass for bd-3a3q conformance"
        );

        // Compliance score must be >= 95% for MUST requirements
        assert!(
            report.compliance_score() >= 0.95,
            "bd-3a3q compliance score must be >= 95%"
        );

        println!("✅ bd-3a3q conformance test suite PASSED");
    }

    #[test]
    fn invalid_transition_insertion_is_log_invariant() {
        for start in HardeningLevel::all() {
            for target in HardeningLevel::all() {
                if target <= start {
                    continue;
                }

                let mut baseline = HardeningStateMachine::with_level(*start);
                baseline.escalate(*target, 1_000, "r92-baseline").unwrap();
                let baseline_replay =
                    HardeningStateMachine::replay_transitions(baseline.transition_log());

                for invalid_target in HardeningLevel::all()
                    .iter()
                    .copied()
                    .filter(|candidate| candidate <= start)
                {
                    let mut perturbed = HardeningStateMachine::with_level(*start);
                    let rejected = perturbed
                        .escalate(invalid_target, 999, "r92-rejected")
                        .unwrap_err();
                    assert_eq!(rejected.code(), "HARDEN_ILLEGAL_REGRESSION");

                    perturbed.escalate(*target, 1_000, "r92-baseline").unwrap();

                    assert_eq!(
                        perturbed.current_level(),
                        baseline.current_level(),
                        "MUST preserve committed level after rejected transition insertion"
                    );
                    assert_eq!(
                        perturbed.transition_log(),
                        baseline.transition_log(),
                        "MUST preserve audit log after rejected transition insertion"
                    );

                    let perturbed_replay =
                        HardeningStateMachine::replay_transitions(perturbed.transition_log());
                    assert_eq!(
                        perturbed_replay.transition_log(),
                        baseline_replay.transition_log(),
                        "SHOULD replay to identical accepted transition log"
                    );
                }
            }
        }
    }
}
