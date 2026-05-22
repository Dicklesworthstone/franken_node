#!/usr/bin/env cargo
//! bd-1ayu: Overhead/rate clamp policy conformance harness.
//!
//! Tests INV-CLAMP-RATE, INV-CLAMP-OVERHEAD, INV-CLAMP-BOUNDS, and
//! INV-CLAMP-DETERMINISTIC to ensure hardening escalation clamp policy
//! enforces deterministic rate and overhead limits in all scenarios.

use std::time::{Duration, Instant};

use frankenengine_node::policy::hardening_clamps::{
    ClampEvent, ClampResult, EscalationBudget, HardeningClampPolicy,
    estimated_overhead_pct,
};
use frankenengine_node::policy::hardening_state_machine::HardeningLevel;

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

fn budget_default() -> EscalationBudget {
    EscalationBudget::default_budget()
}

fn budget_strict() -> EscalationBudget {
    EscalationBudget {
        max_escalations_per_window: 1,
        window_duration_ms: 10_000,
        max_overhead_pct: 10.0,
        min_level: HardeningLevel::Baseline,
        max_level: HardeningLevel::Standard,
    }
}

fn budget_permissive() -> EscalationBudget {
    EscalationBudget {
        max_escalations_per_window: 10,
        window_duration_ms: 60_000,
        max_overhead_pct: 100.0,
        min_level: HardeningLevel::Baseline,
        max_level: HardeningLevel::Critical,
    }
}

fn budget_zero_rate() -> EscalationBudget {
    EscalationBudget {
        max_escalations_per_window: 0,
        window_duration_ms: 60_000,
        max_overhead_pct: 50.0,
        min_level: HardeningLevel::Baseline,
        max_level: HardeningLevel::Critical,
    }
}

fn budget_zero_overhead() -> EscalationBudget {
    EscalationBudget {
        max_escalations_per_window: 5,
        window_duration_ms: 60_000,
        max_overhead_pct: 0.0,
        min_level: HardeningLevel::Baseline,
        max_level: HardeningLevel::Critical,
    }
}

// ---------------------------------------------------------------------------
// INV-CLAMP-RATE Conformance Tests
// ---------------------------------------------------------------------------

fn test_rate_clamp_within_limit() -> Result<(), String> {
    println!("TEST: Rate clamp within limit allows escalation");

    let mut policy = HardeningClampPolicy::new(budget_default());

    // Budget allows 3 escalations per 60s window
    let (result1, _) = policy.check_and_record(
        HardeningLevel::Standard,
        HardeningLevel::Baseline,
        1000,
    );

    match result1 {
        ClampResult::Allowed => {
            println!("✓ First escalation within rate limit allowed");
            Ok(())
        }
        other => Err(format!(
            "Expected Allowed for first escalation, got: {:?}",
            other
        )),
    }
}

fn test_rate_clamp_at_limit() -> Result<(), String> {
    println!("TEST: Rate clamp at limit blocks further escalations");

    let mut policy = HardeningClampPolicy::new(budget_strict()); // max 1 per window

    // First escalation should be allowed
    let (result1, _) = policy.check_and_record(
        HardeningLevel::Standard,
        HardeningLevel::Baseline,
        1000,
    );

    if !matches!(result1, ClampResult::Allowed) {
        return Err(format!("First escalation should be allowed, got: {:?}", result1));
    }

    // Second escalation in same window should be denied
    let (result2, _) = policy.check_escalation(
        HardeningLevel::Enhanced,
        HardeningLevel::Standard,
        2000, // Within 10s window
    );

    match result2 {
        ClampResult::Denied { reason } if reason.contains("rate limit") => {
            println!("✓ Second escalation in window correctly denied");
            Ok(())
        }
        other => Err(format!(
            "Expected rate limit denial for second escalation, got: {:?}",
            other
        )),
    }
}

fn test_rate_clamp_window_expiry() -> Result<(), String> {
    println!("TEST: Rate clamp allows escalation after window expires");

    let mut policy = HardeningClampPolicy::new(budget_strict()); // max 1 per 10s window

    // First escalation
    let (result1, _) = policy.check_and_record(
        HardeningLevel::Standard,
        HardeningLevel::Baseline,
        1000,
    );

    if !matches!(result1, ClampResult::Allowed) {
        return Err(format!("First escalation should be allowed"));
    }

    // Second escalation after window expires
    let (result2, _) = policy.check_escalation(
        HardeningLevel::Enhanced,
        HardeningLevel::Standard,
        20_000, // 19s later, outside 10s window
    );

    match result2 {
        ClampResult::Allowed | ClampResult::Clamped { .. } => {
            println!("✓ Escalation after window expiry allowed");
            Ok(())
        }
        other => Err(format!(
            "Expected escalation after window expiry to be allowed, got: {:?}",
            other
        )),
    }
}

fn test_rate_clamp_zero_budget() -> Result<(), String> {
    println!("TEST: Zero rate budget denies all escalations");

    let mut policy = HardeningClampPolicy::new(budget_zero_rate());

    let (result, _) = policy.check_escalation(
        HardeningLevel::Standard,
        HardeningLevel::Baseline,
        1000,
    );

    match result {
        ClampResult::Denied { reason } if reason.contains("max_escalations_per_window is 0") => {
            println!("✓ Zero rate budget correctly denies escalation");
            Ok(())
        }
        other => Err(format!(
            "Expected denial due to zero rate budget, got: {:?}",
            other
        )),
    }
}

// ---------------------------------------------------------------------------
// INV-CLAMP-OVERHEAD Conformance Tests
// ---------------------------------------------------------------------------

fn test_overhead_clamp_within_budget() -> Result<(), String> {
    println!("TEST: Overhead within budget allows escalation");

    let policy = HardeningClampPolicy::new(budget_permissive()); // 100% overhead budget

    let (result, _) = policy.check_escalation(
        HardeningLevel::Critical,        // 60% overhead
        HardeningLevel::Baseline,        // 0% overhead
        1000,
    );

    match result {
        ClampResult::Allowed => {
            println!("✓ Escalation within overhead budget allowed");
            Ok(())
        }
        other => Err(format!(
            "Expected overhead within budget to be allowed, got: {:?}",
            other
        )),
    }
}

fn test_overhead_clamp_clamping() -> Result<(), String> {
    println!("TEST: Overhead exceeding budget gets clamped");

    let budget = EscalationBudget {
        max_escalations_per_window: 5,
        window_duration_ms: 60_000,
        max_overhead_pct: 10.0, // Standard = 5%, Enhanced = 15%, Maximum = 35%
        min_level: HardeningLevel::Baseline,
        max_level: HardeningLevel::Critical,
    };
    let policy = HardeningClampPolicy::new(budget);

    let (result, _) = policy.check_escalation(
        HardeningLevel::Enhanced,        // 15% overhead, exceeds 10% budget
        HardeningLevel::Baseline,        // 0% overhead
        1000,
    );

    match result {
        ClampResult::Clamped { effective_level, reason } => {
            // Should clamp to Standard (5% overhead, within 10% budget)
            if effective_level == HardeningLevel::Standard && reason.contains("overhead") {
                println!("✓ Overhead exceeding budget correctly clamped to Standard");
                Ok(())
            } else {
                Err(format!(
                    "Expected clamp to Standard with overhead reason, got level: {:?}, reason: {}",
                    effective_level, reason
                ))
            }
        }
        other => Err(format!(
            "Expected overhead clamping, got: {:?}",
            other
        )),
    }
}

fn test_overhead_clamp_denial() -> Result<(), String> {
    println!("TEST: Overhead budget too low denies escalation");

    let policy = HardeningClampPolicy::new(budget_zero_overhead()); // 0% overhead budget

    let (result, _) = policy.check_escalation(
        HardeningLevel::Standard,        // 5% overhead, exceeds 0% budget
        HardeningLevel::Baseline,        // 0% overhead
        1000,
    );

    match result {
        ClampResult::Denied { reason } if reason.contains("overhead limit") => {
            println!("✓ Zero overhead budget correctly denies escalation");
            Ok(())
        }
        other => Err(format!(
            "Expected denial due to overhead limit, got: {:?}",
            other
        )),
    }
}

fn test_overhead_nan_inf_failsafe() -> Result<(), String> {
    println!("TEST: NaN/Inf overhead budget fails closed (treated as 0%)");

    let budget_nan = EscalationBudget {
        max_escalations_per_window: 5,
        window_duration_ms: 60_000,
        max_overhead_pct: f64::NAN,
        min_level: HardeningLevel::Baseline,
        max_level: HardeningLevel::Critical,
    };

    let budget_inf = EscalationBudget {
        max_escalations_per_window: 5,
        window_duration_ms: 60_000,
        max_overhead_pct: f64::INFINITY,
        min_level: HardeningLevel::Baseline,
        max_level: HardeningLevel::Critical,
    };

    let policy_nan = HardeningClampPolicy::new(budget_nan);
    let policy_inf = HardeningClampPolicy::new(budget_inf);

    let (result_nan, _) = policy_nan.check_escalation(
        HardeningLevel::Standard,        // 5% overhead
        HardeningLevel::Baseline,        // 0% overhead
        1000,
    );

    let (result_inf, _) = policy_inf.check_escalation(
        HardeningLevel::Standard,        // 5% overhead
        HardeningLevel::Baseline,        // 0% overhead
        1000,
    );

    // Both NaN and Inf should be treated as 0% overhead budget, denying escalation
    match (&result_nan, &result_inf) {
        (ClampResult::Denied { reason: r1 }, ClampResult::Denied { reason: r2 })
            if r1.contains("overhead limit") && r2.contains("overhead limit") => {
            println!("✓ NaN/Inf overhead budget fail-closed as expected");
            Ok(())
        }
        other => Err(format!(
            "Expected both NaN and Inf to be denied for overhead limit, got: {:?}",
            other
        )),
    }
}

// ---------------------------------------------------------------------------
// INV-CLAMP-BOUNDS Conformance Tests
// ---------------------------------------------------------------------------

fn test_bounds_min_level_floor() -> Result<(), String> {
    println!("TEST: Min level floor enforced");

    let budget = EscalationBudget {
        max_escalations_per_window: 5,
        window_duration_ms: 60_000,
        max_overhead_pct: 100.0,
        min_level: HardeningLevel::Enhanced, // Floor at Enhanced
        max_level: HardeningLevel::Critical,
    };
    let policy = HardeningClampPolicy::new(budget);

    let (result, _) = policy.check_escalation(
        HardeningLevel::Standard,        // Below min_level (Enhanced)
        HardeningLevel::Baseline,
        1000,
    );

    match result {
        ClampResult::Clamped { effective_level, reason } => {
            if effective_level == HardeningLevel::Enhanced && reason.contains("raised to min_level") {
                println!("✓ Min level floor correctly enforced");
                Ok(())
            } else {
                Err(format!(
                    "Expected clamp to Enhanced with min_level reason, got: {:?}, reason: {}",
                    effective_level, reason
                ))
            }
        }
        other => Err(format!(
            "Expected min level clamping, got: {:?}",
            other
        )),
    }
}

fn test_bounds_max_level_ceiling() -> Result<(), String> {
    println!("TEST: Max level ceiling enforced");

    let budget = EscalationBudget {
        max_escalations_per_window: 5,
        window_duration_ms: 60_000,
        max_overhead_pct: 100.0,
        min_level: HardeningLevel::Baseline,
        max_level: HardeningLevel::Standard, // Ceiling at Standard
    };
    let policy = HardeningClampPolicy::new(budget);

    let (result, _) = policy.check_escalation(
        HardeningLevel::Critical,        // Above max_level (Standard)
        HardeningLevel::Baseline,
        1000,
    );

    match result {
        ClampResult::Clamped { effective_level, reason } => {
            if effective_level == HardeningLevel::Standard && reason.contains("capped at max_level") {
                println!("✓ Max level ceiling correctly enforced");
                Ok(())
            } else {
                Err(format!(
                    "Expected clamp to Standard with max_level reason, got: {:?}, reason: {}",
                    effective_level, reason
                ))
            }
        }
        other => Err(format!(
            "Expected max level clamping, got: {:?}",
            other
        )),
    }
}

fn test_bounds_not_escalation() -> Result<(), String> {
    println!("TEST: Non-escalation (downgrade/same) denied");

    let policy = HardeningClampPolicy::new(budget_default());

    // Same level
    let (result1, _) = policy.check_escalation(
        HardeningLevel::Standard,
        HardeningLevel::Standard, // Same level
        1000,
    );

    // Downgrade
    let (result2, _) = policy.check_escalation(
        HardeningLevel::Baseline,
        HardeningLevel::Standard, // Downgrade
        1000,
    );

    match (&result1, &result2) {
        (ClampResult::Denied { reason: r1 }, ClampResult::Denied { reason: r2 })
            if r1.contains("not above current") && r2.contains("not above current") => {
            println!("✓ Non-escalations correctly denied");
            Ok(())
        }
        other => Err(format!(
            "Expected both same-level and downgrade to be denied, got: {:?}",
            other
        )),
    }
}

// ---------------------------------------------------------------------------
// INV-CLAMP-DETERMINISTIC Conformance Tests
// ---------------------------------------------------------------------------

fn test_deterministic_identical_inputs() -> Result<(), String> {
    println!("TEST: Identical inputs produce identical outputs");

    let policy = HardeningClampPolicy::new(budget_default());

    let inputs = [
        (HardeningLevel::Standard, HardeningLevel::Baseline, 5000u64),
        (HardeningLevel::Enhanced, HardeningLevel::Standard, 10000u64),
        (HardeningLevel::Critical, HardeningLevel::Enhanced, 15000u64),
    ];

    for (proposed, current, timestamp) in inputs.iter() {
        let mut results = Vec::new();

        // Run same input 5 times
        for _ in 0..5 {
            let (result, event) = policy.check_escalation(*proposed, *current, *timestamp);
            results.push((result, event));
        }

        // All results should be identical
        let first = &results[0];
        for (i, result) in results.iter().enumerate().skip(1) {
            if std::mem::discriminant(&result.0) != std::mem::discriminant(&first.0) {
                return Err(format!(
                    "Run {}: ClampResult discriminant differs for input ({:?}, {:?}, {})",
                    i + 1, proposed, current, timestamp
                ));
            }

            // Check event determinism
            if result.1.timestamp != first.1.timestamp
                || result.1.proposed_level != first.1.proposed_level
                || result.1.effective_level != first.1.effective_level
            {
                return Err(format!(
                    "Run {}: ClampEvent differs for input ({:?}, {:?}, {})",
                    i + 1, proposed, current, timestamp
                ));
            }

            // Budget utilization should be deterministic
            if (result.1.budget_utilization_pct - first.1.budget_utilization_pct).abs() > 1e-9 {
                return Err(format!(
                    "Run {}: Budget utilization differs: {} vs {}",
                    i + 1, result.1.budget_utilization_pct, first.1.budget_utilization_pct
                ));
            }
        }
    }

    println!("✓ All identical inputs produced identical outputs");
    Ok(())
}

fn test_deterministic_history_order_independence() -> Result<(), String> {
    println!("TEST: History order independence within same window");

    // Create two policies with same escalations in different order
    let mut policy1 = HardeningClampPolicy::new(budget_default());
    let mut policy2 = HardeningClampPolicy::new(budget_default());

    let base_time = 10000u64;
    let window_size = 60000u64;

    // Add escalations in different order but same timestamps
    policy1.record_escalation(base_time + 1000, HardeningLevel::Standard);
    policy1.record_escalation(base_time + 2000, HardeningLevel::Enhanced);

    policy2.record_escalation(base_time + 2000, HardeningLevel::Enhanced);
    policy2.record_escalation(base_time + 1000, HardeningLevel::Standard);

    // Both should have same result for new escalation check
    let test_time = base_time + 3000;
    let (result1, _) = policy1.check_escalation(
        HardeningLevel::Maximum,
        HardeningLevel::Enhanced,
        test_time,
    );
    let (result2, _) = policy2.check_escalation(
        HardeningLevel::Maximum,
        HardeningLevel::Enhanced,
        test_time,
    );

    if std::mem::discriminant(&result1) == std::mem::discriminant(&result2) {
        println!("✓ History order independence maintained");
        Ok(())
    } else {
        Err(format!(
            "History order affected results: {:?} vs {:?}",
            result1, result2
        ))
    }
}

// ---------------------------------------------------------------------------
// Edge Cases and Robustness Tests
// ---------------------------------------------------------------------------

fn test_edge_cases_zero_window_duration() -> Result<(), String> {
    println!("TEST: Zero window duration handled gracefully");

    let budget = EscalationBudget {
        max_escalations_per_window: 3,
        window_duration_ms: 0, // Zero window
        max_overhead_pct: 50.0,
        min_level: HardeningLevel::Baseline,
        max_level: HardeningLevel::Critical,
    };

    let mut policy = HardeningClampPolicy::new(budget);

    // Record some escalations
    policy.record_escalation(1000, HardeningLevel::Standard);
    policy.record_escalation(2000, HardeningLevel::Enhanced);

    // Zero window means all history is "outside window"
    let (result, _) = policy.check_escalation(
        HardeningLevel::Maximum,
        HardeningLevel::Enhanced,
        3000,
    );

    // Should be allowed because zero window means empty window
    if matches!(result, ClampResult::Allowed | ClampResult::Clamped { .. }) {
        println!("✓ Zero window duration handled correctly");
        Ok(())
    } else {
        Err(format!(
            "Expected zero window to allow escalation, got: {:?}",
            result
        ))
    }
}

fn test_edge_cases_extreme_timestamps() -> Result<(), String> {
    println!("TEST: Extreme timestamp values don't cause panics");

    let policy = HardeningClampPolicy::new(budget_default());

    let extreme_cases = [
        (u64::MAX, "max timestamp"),
        (0, "zero timestamp"),
        (u64::MAX / 2, "mid-range timestamp"),
    ];

    for (timestamp, description) in extreme_cases.iter() {
        let (result, _) = policy.check_escalation(
            HardeningLevel::Standard,
            HardeningLevel::Baseline,
            *timestamp,
        );

        // Should not panic and should return some valid result
        match result {
            ClampResult::Allowed | ClampResult::Clamped { .. } | ClampResult::Denied { .. } => {
                println!("  ✓ {} handled without panic", description);
            }
        }
    }

    println!("✓ All extreme timestamps handled gracefully");
    Ok(())
}

// ---------------------------------------------------------------------------
// Performance Regression Tests
// ---------------------------------------------------------------------------

fn test_performance_large_history() -> Result<(), String> {
    println!("TEST: Performance with large escalation history");

    let mut policy = HardeningClampPolicy::new(budget_default());

    // Add many escalations to test performance
    let start_time = 0u64;
    for i in 0..4000 {
        policy.record_escalation(start_time + i, HardeningLevel::Standard);
    }

    let test_start = Instant::now();
    for _ in 0..100 {
        let _ = policy.check_escalation(
            HardeningLevel::Enhanced,
            HardeningLevel::Standard,
            start_time + 5000,
        );
    }
    let duration = test_start.elapsed();

    println!("  Performance: 100 checks with 4K history: {:?}", duration);

    if duration < Duration::from_millis(100) {
        println!("✓ Large history handled efficiently");
        Ok(())
    } else {
        Err(format!(
            "Performance regression: took {:?} for large history",
            duration
        ))
    }
}

// ---------------------------------------------------------------------------
// Main Conformance Runner
// ---------------------------------------------------------------------------

fn main() {
    println!("bd-1ayu: Hardening Clamps Policy Conformance Harness");
    println!("===================================================");

    let mut tests_run = 0;
    let mut tests_passed = 0;
    let mut failures = Vec::new();

    let test_cases = vec![
        ("INV-CLAMP-RATE: Within limit allows escalation", test_rate_clamp_within_limit as fn() -> Result<(), String>),
        ("INV-CLAMP-RATE: At limit blocks further escalations", test_rate_clamp_at_limit),
        ("INV-CLAMP-RATE: Window expiry allows escalation", test_rate_clamp_window_expiry),
        ("INV-CLAMP-RATE: Zero budget denies all escalations", test_rate_clamp_zero_budget),
        ("INV-CLAMP-OVERHEAD: Within budget allows escalation", test_overhead_clamp_within_budget),
        ("INV-CLAMP-OVERHEAD: Exceeding budget gets clamped", test_overhead_clamp_clamping),
        ("INV-CLAMP-OVERHEAD: Too low budget denies escalation", test_overhead_clamp_denial),
        ("INV-CLAMP-OVERHEAD: NaN/Inf budget fails closed", test_overhead_nan_inf_failsafe),
        ("INV-CLAMP-BOUNDS: Min level floor enforced", test_bounds_min_level_floor),
        ("INV-CLAMP-BOUNDS: Max level ceiling enforced", test_bounds_max_level_ceiling),
        ("INV-CLAMP-BOUNDS: Non-escalation denied", test_bounds_not_escalation),
        ("INV-CLAMP-DETERMINISTIC: Identical inputs", test_deterministic_identical_inputs),
        ("INV-CLAMP-DETERMINISTIC: History order independence", test_deterministic_history_order_independence),
        ("EDGE-CASE: Zero window duration", test_edge_cases_zero_window_duration),
        ("EDGE-CASE: Extreme timestamp values", test_edge_cases_extreme_timestamps),
        ("PERF-REGRESSION: Large escalation history", test_performance_large_history),
    ];

    for (test_name, test_fn) in test_cases {
        tests_run += 1;
        println!("\n[{}] {}", tests_run, test_name);

        match test_fn() {
            Ok(()) => {
                tests_passed += 1;
                println!("✅ PASS");
            }
            Err(reason) => {
                failures.push((test_name, reason.clone()));
                println!("❌ FAIL: {}", reason);
            }
        }
    }

    println!("\n===================================================");
    println!("bd-1ayu Conformance Results");
    println!("Passed: {}/{}", tests_passed, tests_run);

    if failures.is_empty() {
        println!("✅ ALL CONFORMANCE TESTS PASSED");
        std::process::exit(0);
    } else {
        println!("❌ {} FAILURES:", failures.len());
        for (test_name, reason) in failures {
            println!("  - {}: {}", test_name, reason);
        }
        std::process::exit(1);
    }
}