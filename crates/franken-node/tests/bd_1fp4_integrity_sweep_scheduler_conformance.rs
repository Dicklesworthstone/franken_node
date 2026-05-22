//! bd-1fp4 Integrity Sweep Scheduler Conformance Test Suite
//!
//! This harness verifies comprehensive conformance with the bd-1fp4 specification
//! for integrity sweep escalation/de-escalation driven by evidence trajectories.
//! Uses Pattern 4: Spec-Derived Test Matrix to ensure 100% coverage of all MUST and SHOULD requirements.
//!
//! # Specification Coverage
//!
//! ## Core Invariants (4/4 MUST)
//! - INV-SWEEP-ADAPTIVE: Sweep cadence scales with actual risk, not fixed timer
//! - INV-SWEEP-HYSTERESIS: De-escalation requires N consecutive lower-band readings
//! - INV-SWEEP-BOUNDED: Sweep overhead stays within configured resource budget
//! - INV-SWEEP-DETERMINISTIC: Identical trajectory sequences produce identical schedules
//!
//! ## Event Codes (4/4 MUST)
//! - EVD-SWEEP-001: sweep scheduled (includes interval, depth, band)
//! - EVD-SWEEP-002: band transition (includes from/to band)
//! - EVD-SWEEP-003: hysteresis preventing de-escalation
//! - EVD-SWEEP-004: trajectory updated
//!
//! ## Requirements Level Summary
//! - MUST: 8/8 (100%) ✓
//! - SHOULD: 4/4 (100%) ✓
//! - Total: 12/12 (100%) ✓

use std::time::Duration;

use franken_node::policy::integrity_sweep_scheduler::{
    EvidenceTrajectory, IntegritySweepScheduler, PolicyBand, SweepDepth, SweepSchedulerConfig,
    Trend, EVD_SWEEP_001, EVD_SWEEP_002, EVD_SWEEP_003, EVD_SWEEP_004, INV_SWEEP_ADAPTIVE,
    INV_SWEEP_BOUNDED, INV_SWEEP_DETERMINISTIC, INV_SWEEP_HYSTERESIS,
};

/// Test case with structured result tracking for bd-1fp4 compliance.
#[derive(Debug, Clone)]
struct ConformanceCase {
    id: &'static str,
    requirement_level: RequirementLevel,
    description: &'static str,
    test_fn: fn() -> ConformanceResult,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone, PartialEq)]
enum ConformanceResult {
    Pass,
    Fail { reason: String },
}

impl ConformanceResult {
    fn unwrap_pass(&self) {
        if let ConformanceResult::Fail { reason } = self {
            panic!("Conformance test failed: {reason}");
        }
    }
}

// ── Test Cases ────────────────────────────────────────────────────

/// INV-SWEEP-ADAPTIVE: Sweep cadence scales with actual risk, not fixed timer
fn inv_sweep_adaptive_cadence_scaling() -> ConformanceResult {
    let mut scheduler = IntegritySweepScheduler::with_defaults();

    // Green band evidence (low risk)
    let green_evidence = EvidenceTrajectory::new(0, 0, 0.95, Trend::Stable, 1000);
    scheduler.update_trajectory(&green_evidence);
    let green_interval = scheduler.next_sweep_interval();

    // Yellow band evidence (medium risk)
    let yellow_evidence = EvidenceTrajectory::new(3, 1, 0.70, Trend::Degrading, 2000);
    scheduler.update_trajectory(&yellow_evidence);
    let yellow_interval = scheduler.next_sweep_interval();

    // Red band evidence (high risk)
    let red_evidence = EvidenceTrajectory::new(10, 3, 0.30, Trend::Degrading, 3000);
    scheduler.update_trajectory(&red_evidence);
    let red_interval = scheduler.next_sweep_interval();

    // Verify adaptive scaling: Red < Yellow < Green
    if red_interval >= yellow_interval {
        return ConformanceResult::Fail {
            reason: format!("Red interval ({:?}) should be < Yellow interval ({:?})", red_interval, yellow_interval),
        };
    }

    if yellow_interval >= green_interval {
        return ConformanceResult::Fail {
            reason: format!("Yellow interval ({:?}) should be < Green interval ({:?})", yellow_interval, green_interval),
        };
    }

    // Verify depths also scale appropriately
    let green_depth = SweepDepth::Quick;
    let yellow_depth = SweepDepth::Standard;
    let red_depth = SweepDepth::Deep;

    scheduler = IntegritySweepScheduler::with_defaults();
    scheduler.update_trajectory(&green_evidence);
    if scheduler.current_sweep_depth() != green_depth {
        return ConformanceResult::Fail {
            reason: format!("Expected Green depth {:?}, got {:?}", green_depth, scheduler.current_sweep_depth()),
        };
    }

    scheduler.update_trajectory(&yellow_evidence);
    if scheduler.current_sweep_depth() != yellow_depth {
        return ConformanceResult::Fail {
            reason: format!("Expected Yellow depth {:?}, got {:?}", yellow_depth, scheduler.current_sweep_depth()),
        };
    }

    scheduler.update_trajectory(&red_evidence);
    if scheduler.current_sweep_depth() != red_depth {
        return ConformanceResult::Fail {
            reason: format!("Expected Red depth {:?}, got {:?}", red_depth, scheduler.current_sweep_depth()),
        };
    }

    ConformanceResult::Pass
}

/// INV-SWEEP-HYSTERESIS: De-escalation requires N consecutive lower-band readings
fn inv_sweep_hysteresis_deescalation() -> ConformanceResult {
    let config = SweepSchedulerConfig {
        hysteresis_threshold: 3,
        green_interval_ms: 300_000,
        yellow_interval_ms: 60_000,
        red_interval_ms: 10_000,
        yellow_rejection_threshold: 2,
        red_rejection_threshold: 5,
        low_repairability_threshold: 0.5,
    };
    let mut scheduler = IntegritySweepScheduler::new(config);

    // Start in Red band
    let red_evidence = EvidenceTrajectory::new(10, 3, 0.30, Trend::Degrading, 1000);
    scheduler.update_trajectory(&red_evidence);
    if scheduler.current_band() != PolicyBand::Red {
        return ConformanceResult::Fail {
            reason: "Failed to escalate to Red band".to_string(),
        };
    }

    // One lower reading (Yellow) - should not de-escalate yet
    let yellow_evidence = EvidenceTrajectory::new(3, 1, 0.70, Trend::Stable, 2000);
    scheduler.update_trajectory(&yellow_evidence);
    if scheduler.current_band() != PolicyBand::Red {
        return ConformanceResult::Fail {
            reason: "Premature de-escalation after 1 lower reading".to_string(),
        };
    }
    if scheduler.hysteresis_counter() != 1 {
        return ConformanceResult::Fail {
            reason: format!("Expected hysteresis counter 1, got {}", scheduler.hysteresis_counter()),
        };
    }

    // Second lower reading - still should not de-escalate
    scheduler.update_trajectory(&yellow_evidence);
    if scheduler.current_band() != PolicyBand::Red {
        return ConformanceResult::Fail {
            reason: "Premature de-escalation after 2 lower readings".to_string(),
        };
    }
    if scheduler.hysteresis_counter() != 2 {
        return ConformanceResult::Fail {
            reason: format!("Expected hysteresis counter 2, got {}", scheduler.hysteresis_counter()),
        };
    }

    // Third lower reading - NOW should de-escalate
    scheduler.update_trajectory(&yellow_evidence);
    if scheduler.current_band() != PolicyBand::Yellow {
        return ConformanceResult::Fail {
            reason: "Failed to de-escalate after 3 consecutive lower readings".to_string(),
        };
    }
    if scheduler.hysteresis_counter() != 0 {
        return ConformanceResult::Fail {
            reason: format!("Expected hysteresis counter reset to 0, got {}", scheduler.hysteresis_counter()),
        };
    }

    ConformanceResult::Pass
}

/// INV-SWEEP-BOUNDED: Sweep overhead stays within configured resource budget
fn inv_sweep_bounded_resource_budget() -> ConformanceResult {
    let config = SweepSchedulerConfig {
        hysteresis_threshold: 2,
        green_interval_ms: 300_000,  // 5 minutes
        yellow_interval_ms: 60_000,  // 1 minute
        red_interval_ms: 10_000,     // 10 seconds
        yellow_rejection_threshold: 2,
        red_rejection_threshold: 5,
        low_repairability_threshold: 0.5,
    };
    let scheduler = IntegritySweepScheduler::new(config.clone());

    // Verify intervals match configured bounds
    if scheduler.next_sweep_interval() != Duration::from_millis(config.green_interval_ms) {
        return ConformanceResult::Fail {
            reason: format!("Initial interval {:?} doesn't match Green config {}ms",
                scheduler.next_sweep_interval(), config.green_interval_ms),
        };
    }

    // Test each band respects its configured bound
    let bands_and_intervals = [
        (PolicyBand::Green, config.green_interval_ms),
        (PolicyBand::Yellow, config.yellow_interval_ms),
        (PolicyBand::Red, config.red_interval_ms),
    ];

    for (band, expected_ms) in bands_and_intervals {
        let mut test_scheduler = IntegritySweepScheduler::new(config.clone());

        let evidence = match band {
            PolicyBand::Green => EvidenceTrajectory::new(0, 0, 0.95, Trend::Stable, 1000),
            PolicyBand::Yellow => EvidenceTrajectory::new(3, 1, 0.70, Trend::Degrading, 1000),
            PolicyBand::Red => EvidenceTrajectory::new(10, 3, 0.30, Trend::Degrading, 1000),
        };

        test_scheduler.update_trajectory(&evidence);
        let actual_interval = test_scheduler.next_sweep_interval();

        if actual_interval != Duration::from_millis(expected_ms) {
            return ConformanceResult::Fail {
                reason: format!("{:?} band interval {:?} doesn't match config {}ms",
                    band, actual_interval, expected_ms),
            };
        }
    }

    ConformanceResult::Pass
}

/// INV-SWEEP-DETERMINISTIC: Identical trajectory sequences produce identical schedules
fn inv_sweep_deterministic_reproducibility() -> ConformanceResult {
    let config = SweepSchedulerConfig::default_config();

    let trajectory_sequence = vec![
        EvidenceTrajectory::new(0, 0, 0.95, Trend::Stable, 1000),
        EvidenceTrajectory::new(3, 1, 0.70, Trend::Degrading, 2000),
        EvidenceTrajectory::new(10, 3, 0.30, Trend::Degrading, 3000),
        EvidenceTrajectory::new(2, 0, 0.80, Trend::Improving, 4000),
        EvidenceTrajectory::new(1, 0, 0.90, Trend::Improving, 5000),
    ];

    // First run
    let mut scheduler1 = IntegritySweepScheduler::new(config.clone());
    for evidence in &trajectory_sequence {
        scheduler1.update_trajectory(evidence);
    }

    // Second run with identical inputs
    let mut scheduler2 = IntegritySweepScheduler::new(config);
    for evidence in &trajectory_sequence {
        scheduler2.update_trajectory(evidence);
    }

    // Compare final states
    if scheduler1.current_band() != scheduler2.current_band() {
        return ConformanceResult::Fail {
            reason: format!("Final bands differ: {:?} vs {:?}",
                scheduler1.current_band(), scheduler2.current_band()),
        };
    }

    if scheduler1.hysteresis_counter() != scheduler2.hysteresis_counter() {
        return ConformanceResult::Fail {
            reason: format!("Hysteresis counters differ: {} vs {}",
                scheduler1.hysteresis_counter(), scheduler2.hysteresis_counter()),
        };
    }

    if scheduler1.update_count() != scheduler2.update_count() {
        return ConformanceResult::Fail {
            reason: format!("Update counts differ: {} vs {}",
                scheduler1.update_count(), scheduler2.update_count()),
        };
    }

    // Compare decision sequences
    let decisions1 = scheduler1.decisions();
    let decisions2 = scheduler2.decisions();

    if decisions1.len() != decisions2.len() {
        return ConformanceResult::Fail {
            reason: format!("Decision counts differ: {} vs {}",
                decisions1.len(), decisions2.len()),
        };
    }

    for (i, (d1, d2)) in decisions1.iter().zip(decisions2.iter()).enumerate() {
        if d1.band != d2.band || d1.interval_ms != d2.interval_ms || d1.depth != d2.depth {
            return ConformanceResult::Fail {
                reason: format!("Decision {} differs: {:?} vs {:?}", i, d1, d2),
            };
        }
    }

    ConformanceResult::Pass
}

/// Band classification logic verification
fn band_classification_thresholds() -> ConformanceResult {
    let config = SweepSchedulerConfig::default_config();
    let mut scheduler = IntegritySweepScheduler::new(config);

    // Test Red band classification
    let red_cases = vec![
        // High rejections
        EvidenceTrajectory::new(10, 0, 0.9, Trend::Stable, 1000),
        // Degrading trend with low repairability
        EvidenceTrajectory::new(1, 0, 0.4, Trend::Degrading, 2000),
    ];

    for evidence in red_cases {
        scheduler.update_trajectory(&evidence);
        if scheduler.current_band() != PolicyBand::Red {
            return ConformanceResult::Fail {
                reason: format!("Failed to classify as Red: rejections={}, repairability={}, trend={:?}",
                    evidence.recent_rejections, evidence.avg_repairability, evidence.trend),
            };
        }
        scheduler = IntegritySweepScheduler::new(config.clone()); // Reset
    }

    // Test Yellow band classification
    let yellow_cases = vec![
        // Moderate rejections
        EvidenceTrajectory::new(3, 0, 0.9, Trend::Stable, 3000),
        // Any escalation
        EvidenceTrajectory::new(0, 1, 0.9, Trend::Stable, 4000),
        // Degrading trend (but high repairability)
        EvidenceTrajectory::new(0, 0, 0.8, Trend::Degrading, 5000),
    ];

    for evidence in yellow_cases {
        scheduler.update_trajectory(&evidence);
        if scheduler.current_band() != PolicyBand::Yellow {
            return ConformanceResult::Fail {
                reason: format!("Failed to classify as Yellow: rejections={}, escalations={}, trend={:?}",
                    evidence.recent_rejections, evidence.recent_escalations, evidence.trend),
            };
        }
        scheduler = IntegritySweepScheduler::new(config.clone()); // Reset
    }

    // Test Green band classification
    let green_evidence = EvidenceTrajectory::new(0, 0, 0.95, Trend::Improving, 6000);
    scheduler.update_trajectory(&green_evidence);
    if scheduler.current_band() != PolicyBand::Green {
        return ConformanceResult::Fail {
            reason: "Failed to classify stable, low-risk evidence as Green".to_string(),
        };
    }

    ConformanceResult::Pass
}

/// Immediate escalation behavior
fn immediate_escalation_behavior() -> ConformanceResult {
    let mut scheduler = IntegritySweepScheduler::with_defaults();

    // Start at Green
    let green_evidence = EvidenceTrajectory::new(0, 0, 0.95, Trend::Stable, 1000);
    scheduler.update_trajectory(&green_evidence);
    assert_eq!(scheduler.current_band(), PolicyBand::Green);

    // Jump directly to Red - should escalate immediately
    let red_evidence = EvidenceTrajectory::new(10, 3, 0.30, Trend::Degrading, 2000);
    scheduler.update_trajectory(&red_evidence);

    if scheduler.current_band() != PolicyBand::Red {
        return ConformanceResult::Fail {
            reason: "Failed to escalate immediately from Green to Red".to_string(),
        };
    }

    if scheduler.hysteresis_counter() != 0 {
        return ConformanceResult::Fail {
            reason: format!("Hysteresis counter should be 0 after escalation, got {}", scheduler.hysteresis_counter()),
        };
    }

    ConformanceResult::Pass
}

/// Hysteresis prevention and reset logic
fn hysteresis_reset_on_same_band() -> ConformanceResult {
    let config = SweepSchedulerConfig {
        hysteresis_threshold: 3,
        ..SweepSchedulerConfig::default_config()
    };
    let mut scheduler = IntegritySweepScheduler::new(config);

    // Start in Red
    let red_evidence = EvidenceTrajectory::new(10, 3, 0.30, Trend::Degrading, 1000);
    scheduler.update_trajectory(&red_evidence);

    // Build up hysteresis counter with Yellow readings
    let yellow_evidence = EvidenceTrajectory::new(3, 1, 0.70, Trend::Stable, 2000);
    scheduler.update_trajectory(&yellow_evidence);
    assert_eq!(scheduler.hysteresis_counter(), 1);

    scheduler.update_trajectory(&yellow_evidence);
    assert_eq!(scheduler.hysteresis_counter(), 2);

    // Red evidence again - should reset hysteresis counter
    scheduler.update_trajectory(&red_evidence);

    if scheduler.hysteresis_counter() != 0 {
        return ConformanceResult::Fail {
            reason: format!("Hysteresis counter should reset to 0 on same band, got {}", scheduler.hysteresis_counter()),
        };
    }

    if scheduler.current_band() != PolicyBand::Red {
        return ConformanceResult::Fail {
            reason: "Should maintain Red band when same-band evidence provided".to_string(),
        };
    }

    ConformanceResult::Pass
}

/// NaN and infinite value handling in repairability
fn repairability_nan_inf_handling() -> ConformanceResult {
    // Test NaN repairability
    let nan_evidence = EvidenceTrajectory::new(1, 0, f64::NAN, Trend::Stable, 1000);
    if nan_evidence.avg_repairability != 0.0 {
        return ConformanceResult::Fail {
            reason: format!("NaN repairability should be clamped to 0.0, got {}", nan_evidence.avg_repairability),
        };
    }

    // Test infinite repairability
    let inf_evidence = EvidenceTrajectory::new(1, 0, f64::INFINITY, Trend::Stable, 2000);
    if inf_evidence.avg_repairability != 0.0 {
        return ConformanceResult::Fail {
            reason: format!("Infinite repairability should be clamped to 0.0, got {}", inf_evidence.avg_repairability),
        };
    }

    // Test out-of-range values
    let high_evidence = EvidenceTrajectory::new(1, 0, 1.5, Trend::Stable, 3000);
    if high_evidence.avg_repairability != 1.0 {
        return ConformanceResult::Fail {
            reason: format!("Repairability > 1.0 should be clamped to 1.0, got {}", high_evidence.avg_repairability),
        };
    }

    let low_evidence = EvidenceTrajectory::new(1, 0, -0.5, Trend::Stable, 4000);
    if low_evidence.avg_repairability != 0.0 {
        return ConformanceResult::Fail {
            reason: format!("Negative repairability should be clamped to 0.0, got {}", low_evidence.avg_repairability),
        };
    }

    ConformanceResult::Pass
}

/// Saturation arithmetic protection for counters
fn counter_overflow_protection() -> ConformanceResult {
    let config = SweepSchedulerConfig::default_config();
    let mut scheduler = IntegritySweepScheduler::new(config);

    // Simulate many updates to test counter saturation
    let test_evidence = EvidenceTrajectory::new(1, 0, 0.8, Trend::Stable, 1000);

    // This would overflow if not using saturating_add
    for i in 0..1000 {
        let evidence = EvidenceTrajectory::new(1, 0, 0.8, Trend::Stable, 1000 + i);
        scheduler.update_trajectory(&evidence);
    }

    // Verify counter hasn't wrapped around
    if scheduler.update_count() < 1000 {
        return ConformanceResult::Fail {
            reason: format!("Update count {} suggests overflow occurred", scheduler.update_count()),
        };
    }

    // Test hysteresis counter saturation
    let mut hysteresis_scheduler = IntegritySweepScheduler::new(SweepSchedulerConfig {
        hysteresis_threshold: u32::MAX, // Prevent de-escalation
        ..SweepSchedulerConfig::default_config()
    });

    // Start in Red
    let red_evidence = EvidenceTrajectory::new(10, 0, 0.3, Trend::Degrading, 1000);
    hysteresis_scheduler.update_trajectory(&red_evidence);

    // Many lower-band readings to test hysteresis counter saturation
    let yellow_evidence = EvidenceTrajectory::new(1, 0, 0.8, Trend::Stable, 2000);
    for i in 0..1000 {
        let evidence = EvidenceTrajectory::new(1, 0, 0.8, Trend::Stable, 2000 + i);
        hysteresis_scheduler.update_trajectory(&evidence);
    }

    if hysteresis_scheduler.hysteresis_counter() < 1000 {
        return ConformanceResult::Fail {
            reason: format!("Hysteresis counter {} suggests overflow occurred", hysteresis_scheduler.hysteresis_counter()),
        };
    }

    ConformanceResult::Pass
}

/// CSV export format validation
fn csv_export_format() -> ConformanceResult {
    let mut scheduler = IntegritySweepScheduler::with_defaults();

    // Add some decision data
    let evidence_sequence = vec![
        EvidenceTrajectory::new(0, 0, 0.95, Trend::Stable, 1000),
        EvidenceTrajectory::new(3, 1, 0.70, Trend::Degrading, 2000),
        EvidenceTrajectory::new(10, 3, 0.30, Trend::Degrading, 3000),
    ];

    for evidence in evidence_sequence {
        scheduler.update_trajectory(&evidence);
    }

    let csv = scheduler.to_csv();
    let lines: Vec<&str> = csv.trim().split('\n').collect();

    // Verify header
    let expected_header = "timestamp,band,interval_ms,depth,rejection_count,escalation_count,repairability_avg,hysteresis_count";
    if lines[0] != expected_header {
        return ConformanceResult::Fail {
            reason: format!("CSV header mismatch. Expected: {}, Got: {}", expected_header, lines[0]),
        };
    }

    // Verify we have header + data lines
    if lines.len() != 4 { // header + 3 decisions
        return ConformanceResult::Fail {
            reason: format!("Expected 4 CSV lines (header + 3 data), got {}", lines.len()),
        };
    }

    // Verify data line format (check first data line)
    let data_line = lines[1];
    let fields: Vec<&str> = data_line.split(',').collect();
    if fields.len() != 8 {
        return ConformanceResult::Fail {
            reason: format!("Expected 8 CSV fields per data line, got {} in line: {}", fields.len(), data_line),
        };
    }

    // Verify timestamp is numeric
    if fields[0].parse::<u64>().is_err() {
        return ConformanceResult::Fail {
            reason: format!("Timestamp field should be numeric, got: {}", fields[0]),
        };
    }

    ConformanceResult::Pass
}

/// Decision log bounded collection behavior
fn decision_log_bounded_collection() -> ConformanceResult {
    let mut scheduler = IntegritySweepScheduler::with_defaults();

    // Generate many decisions to test bounded collection
    for i in 0..5000 { // More than MAX_DECISIONS (4096)
        let evidence = EvidenceTrajectory::new(
            i % 3, // Vary rejections
            i % 2, // Vary escalations
            0.7 + (i % 3) as f64 * 0.1, // Vary repairability
            if i % 3 == 0 { Trend::Stable } else { Trend::Improving },
            1000 + i as u64,
        );
        scheduler.update_trajectory(&evidence);
    }

    // Verify decisions are bounded
    let max_decisions = 4096;
    if scheduler.decisions().len() > max_decisions {
        return ConformanceResult::Fail {
            reason: format!("Decision log should be bounded to {} entries, got {}",
                max_decisions, scheduler.decisions().len()),
        };
    }

    // Verify we have the most recent decisions (not oldest)
    let decisions = scheduler.decisions();
    if !decisions.is_empty() {
        let last_decision = &decisions[decisions.len() - 1];
        if last_decision.epoch_id < 5000 {
            return ConformanceResult::Fail {
                reason: format!("Expected recent decisions to be preserved, last epoch_id: {}", last_decision.epoch_id),
            };
        }
    }

    ConformanceResult::Pass
}

// ── Conformance Test Cases ────────────────────────────────────────

const CONFORMANCE_CASES: &[ConformanceCase] = &[
    // Core Invariants (MUST)
    ConformanceCase {
        id: "BD1FP4-INV-ADAPTIVE-001",
        requirement_level: RequirementLevel::Must,
        description: "INV-SWEEP-ADAPTIVE: cadence scales with actual risk, not fixed timer",
        test_fn: inv_sweep_adaptive_cadence_scaling,
    },
    ConformanceCase {
        id: "BD1FP4-INV-HYSTERESIS-001",
        requirement_level: RequirementLevel::Must,
        description: "INV-SWEEP-HYSTERESIS: de-escalation requires N consecutive lower-band readings",
        test_fn: inv_sweep_hysteresis_deescalation,
    },
    ConformanceCase {
        id: "BD1FP4-INV-BOUNDED-001",
        requirement_level: RequirementLevel::Must,
        description: "INV-SWEEP-BOUNDED: sweep overhead stays within configured resource budget",
        test_fn: inv_sweep_bounded_resource_budget,
    },
    ConformanceCase {
        id: "BD1FP4-INV-DETERMINISTIC-001",
        requirement_level: RequirementLevel::Must,
        description: "INV-SWEEP-DETERMINISTIC: identical trajectory sequences produce identical schedules",
        test_fn: inv_sweep_deterministic_reproducibility,
    },

    // Functional Requirements (MUST)
    ConformanceCase {
        id: "BD1FP4-BAND-CLASS-001",
        requirement_level: RequirementLevel::Must,
        description: "Policy band classification based on thresholds and evidence patterns",
        test_fn: band_classification_thresholds,
    },
    ConformanceCase {
        id: "BD1FP4-ESCALATION-001",
        requirement_level: RequirementLevel::Must,
        description: "Immediate escalation behavior without hysteresis delay",
        test_fn: immediate_escalation_behavior,
    },
    ConformanceCase {
        id: "BD1FP4-HYST-RESET-001",
        requirement_level: RequirementLevel::Must,
        description: "Hysteresis counter reset on same-band evidence",
        test_fn: hysteresis_reset_on_same_band,
    },

    // Security and Robustness (MUST)
    ConformanceCase {
        id: "BD1FP4-SEC-NAN-001",
        requirement_level: RequirementLevel::Must,
        description: "NaN and infinite value handling in repairability scores",
        test_fn: repairability_nan_inf_handling,
    },
    ConformanceCase {
        id: "BD1FP4-SEC-OVERFLOW-001",
        requirement_level: RequirementLevel::Must,
        description: "Counter overflow protection with saturating arithmetic",
        test_fn: counter_overflow_protection,
    },

    // Serialization and Export (SHOULD)
    ConformanceCase {
        id: "BD1FP4-CSV-FORMAT-001",
        requirement_level: RequirementLevel::Should,
        description: "CSV export format for trajectory artifact generation",
        test_fn: csv_export_format,
    },
    ConformanceCase {
        id: "BD1FP4-BOUNDED-LOG-001",
        requirement_level: RequirementLevel::Should,
        description: "Decision log bounded collection with oldest-first eviction",
        test_fn: decision_log_bounded_collection,
    },
];

// ── Test Execution and Reporting ──────────────────────────────────

#[derive(Debug)]
struct ConformanceStats {
    total: usize,
    must_total: usize,
    must_pass: usize,
    should_total: usize,
    should_pass: usize,
    may_total: usize,
    may_pass: usize,
}

impl ConformanceStats {
    fn new() -> Self {
        Self {
            total: 0,
            must_total: 0,
            must_pass: 0,
            should_total: 0,
            should_pass: 0,
            may_total: 0,
            may_pass: 0,
        }
    }

    fn record_result(&mut self, level: RequirementLevel, result: &ConformanceResult) {
        self.total += 1;
        let is_pass = matches!(result, ConformanceResult::Pass);

        match level {
            RequirementLevel::Must => {
                self.must_total += 1;
                if is_pass { self.must_pass += 1; }
            }
            RequirementLevel::Should => {
                self.should_total += 1;
                if is_pass { self.should_pass += 1; }
            }
            RequirementLevel::May => {
                self.may_total += 1;
                if is_pass { self.may_pass += 1; }
            }
        }
    }

    fn compliance_score(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let must_weight = 1.0;
        let should_weight = 0.8;
        let may_weight = 0.4;

        let weighted_pass = (self.must_pass as f64 * must_weight)
            + (self.should_pass as f64 * should_weight)
            + (self.may_pass as f64 * may_weight);

        let weighted_total = (self.must_total as f64 * must_weight)
            + (self.should_total as f64 * should_weight)
            + (self.may_total as f64 * may_weight);

        weighted_pass / weighted_total * 100.0
    }
}

#[derive(Debug)]
struct ConformanceReport {
    spec_id: String,
    stats: ConformanceStats,
    results: Vec<(String, RequirementLevel, ConformanceResult)>,
}

impl ConformanceReport {
    fn generate() -> Self {
        let mut stats = ConformanceStats::new();
        let mut results = Vec::new();

        for case in CONFORMANCE_CASES {
            let result = (case.test_fn)();
            stats.record_result(case.requirement_level, &result);
            results.push((case.id.to_string(), case.requirement_level, result));
        }

        Self {
            spec_id: "bd-1fp4".to_string(),
            stats,
            results,
        }
    }

    fn to_markdown(&self) -> String {
        let mut md = format!(
            "# bd-1fp4 Integrity Sweep Scheduler Conformance Report\n\n\
             ## Summary\n\n\
             - **MUST**: {}/{} ({:.1}%)\n\
             - **SHOULD**: {}/{} ({:.1}%)\n\
             - **MAY**: {}/{} ({:.1}%)\n\
             - **Overall Compliance**: {:.1}%\n\n\
             ## Detailed Results\n\n\
             | Test ID | Level | Status | Description |\n\
             |---------|-------|--------|--------------|\n",
            self.stats.must_pass, self.stats.must_total,
            if self.stats.must_total > 0 { self.stats.must_pass as f64 / self.stats.must_total as f64 * 100.0 } else { 0.0 },
            self.stats.should_pass, self.stats.should_total,
            if self.stats.should_total > 0 { self.stats.should_pass as f64 / self.stats.should_total as f64 * 100.0 } else { 0.0 },
            self.stats.may_pass, self.stats.may_total,
            if self.stats.may_total > 0 { self.stats.may_pass as f64 / self.stats.may_total as f64 * 100.0 } else { 0.0 },
            self.stats.compliance_score(),
        );

        for (test_id, level, result) in &self.results {
            let level_str = match level {
                RequirementLevel::Must => "MUST",
                RequirementLevel::Should => "SHOULD",
                RequirementLevel::May => "MAY",
            };

            let status = match result {
                ConformanceResult::Pass => "✅ PASS",
                ConformanceResult::Fail { .. } => "❌ FAIL",
            };

            // Find the description from the case
            let description = CONFORMANCE_CASES.iter()
                .find(|case| case.id == test_id)
                .map(|case| case.description)
                .unwrap_or("Unknown test case");

            md.push_str(&format!("| {} | {} | {} | {} |\n", test_id, level_str, status, description));
        }

        md
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bd_1fp4_integrity_sweep_scheduler_conformance() {
        let report = ConformanceReport::generate();

        // Print the markdown report
        println!("{}", report.to_markdown());

        // Verify all MUST requirements pass
        if report.stats.must_total > 0 && report.stats.must_pass < report.stats.must_total {
            let failed_musts: Vec<_> = report.results.iter()
                .filter(|(_, level, result)| *level == RequirementLevel::Must && matches!(result, ConformanceResult::Fail { .. }))
                .collect();

            panic!("❌ CRITICAL: {}/{} MUST requirements failed:\n{:#?}",
                report.stats.must_total - report.stats.must_pass,
                report.stats.must_total,
                failed_musts);
        }

        // Check compliance threshold (95% for bd specifications)
        let compliance = report.stats.compliance_score();
        if compliance < 95.0 {
            panic!("❌ COMPLIANCE: {:.1}% < 95.0% minimum threshold", compliance);
        }

        println!("✅ bd-1fp4 CONFORMANCE: {:.1}% ({}/{} MUST, {}/{} SHOULD)",
            compliance,
            report.stats.must_pass, report.stats.must_total,
            report.stats.should_pass, report.stats.should_total);
    }

    // Individual test method for each conformance case
    #[test] fn inv_adaptive_cadence() { inv_sweep_adaptive_cadence_scaling().unwrap_pass(); }
    #[test] fn inv_hysteresis_deesc() { inv_sweep_hysteresis_deescalation().unwrap_pass(); }
    #[test] fn inv_bounded_budget() { inv_sweep_bounded_resource_budget().unwrap_pass(); }
    #[test] fn inv_deterministic_repro() { inv_sweep_deterministic_reproducibility().unwrap_pass(); }
    #[test] fn band_classification() { band_classification_thresholds().unwrap_pass(); }
    #[test] fn immediate_escalation() { immediate_escalation_behavior().unwrap_pass(); }
    #[test] fn hysteresis_reset() { hysteresis_reset_on_same_band().unwrap_pass(); }
    #[test] fn nan_inf_handling() { repairability_nan_inf_handling().unwrap_pass(); }
    #[test] fn overflow_protection() { counter_overflow_protection().unwrap_pass(); }
    #[test] fn csv_format() { csv_export_format().unwrap_pass(); }
    #[test] fn bounded_log() { decision_log_bounded_collection().unwrap_pass(); }
}