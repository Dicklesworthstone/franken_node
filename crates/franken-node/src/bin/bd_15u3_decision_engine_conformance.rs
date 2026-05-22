#!/usr/bin/env cargo
//! bd-15u3: Guardrail precedence enforcement conformance harness.
//!
//! Tests INV-DECIDE-PRECEDENCE, INV-DECIDE-DETERMINISTIC, and INV-DECIDE-NO-PANIC
//! to ensure the decision engine properly enforces guardrail precedence over
//! Bayesian rankings in all scenarios.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use frankenengine_node::policy::bayesian_diagnostics::{CandidateRef, RankedCandidate};
use frankenengine_node::policy::decision_engine::{
    DecisionEngine, DecisionOutcome, DecisionReason, GuardrailId,
};
use frankenengine_node::policy::guardrail_monitor::{
    GuardrailMonitorSet, GuardrailVerdict, SystemState, MemoryBudgetGuardrail,
    MonitorId, MonitorBudgetId,
};
use frankenengine_node::policy::hardening_state_machine::HardeningLevel;

// ---------------------------------------------------------------------------
// Conformance Test Cases
// ---------------------------------------------------------------------------

/// Create a test candidate reference.
fn candidate_ref(id: &str) -> CandidateRef {
    CandidateRef::new(id)
}

/// Create a ranked candidate with specified guardrail filter state.
fn ranked_candidate(
    id: &str,
    posterior: f64,
    guardrail_filtered: bool,
) -> RankedCandidate {
    RankedCandidate {
        candidate_ref: candidate_ref(id),
        posterior_prob: posterior,
        prior_prob: 0.5,
        observation_count: 10,
        confidence_interval: (posterior - 0.1, posterior + 0.1),
        guardrail_filtered,
    }
}

/// Create a healthy system state (no guardrail violations).
fn healthy_system_state() -> SystemState {
    SystemState {
        memory_used_bytes: 500_000_000,
        memory_budget_bytes: 1_000_000_000,
        durability_level: 0.99,
        hardening_level: HardeningLevel::Standard,
        proposed_hardening_level: None,
        evidence_emission_active: true,
        memory_tail_risk: None,
        reliability_telemetry: None,
        epoch_id: 42,
    }
}

/// Create a system state that violates memory budget guardrail.
fn over_budget_system_state() -> SystemState {
    SystemState {
        memory_used_bytes: 950_000_000, // 95% of budget, triggers violation
        memory_budget_bytes: 1_000_000_000,
        durability_level: 0.99,
        hardening_level: HardeningLevel::Standard,
        proposed_hardening_level: None,
        evidence_emission_active: true,
        memory_tail_risk: None,
        reliability_telemetry: None,
        epoch_id: 42,
    }
}

/// Create default guardrail monitor set.
fn default_monitors() -> GuardrailMonitorSet {
    GuardrailMonitorSet::with_defaults()
}

// ---------------------------------------------------------------------------
// INV-DECIDE-PRECEDENCE Conformance Tests
// ---------------------------------------------------------------------------

fn test_precedence_top_candidate_passes_all_guardrails() -> Result<(), String> {
    println!("TEST: Top candidate passes all guardrails");

    let engine = DecisionEngine::new(123);
    let candidates = vec![
        ranked_candidate("high-score", 0.9, false), // Top choice
        ranked_candidate("low-score", 0.1, false),  // Backup
    ];
    let monitors = default_monitors();
    let state = healthy_system_state();

    let outcome = engine.decide(&candidates, &monitors, &state);

    // Should choose top candidate since no guardrails block it
    match outcome.reason {
        DecisionReason::TopCandidateAccepted => {
            if outcome.chosen == Some(candidate_ref("high-score")) {
                println!("✓ Top candidate correctly chosen");
                Ok(())
            } else {
                Err(format!("Wrong candidate chosen: {:?}", outcome.chosen))
            }
        }
        other => Err(format!("Wrong reason: {:?}", other)),
    }
}

fn test_precedence_top_candidate_blocked_fallback_used() -> Result<(), String> {
    println!("TEST: Top candidate blocked, fallback used");

    let engine = DecisionEngine::new(123);
    let candidates = vec![
        ranked_candidate("high-score", 0.9, true),  // Blocked by guardrail
        ranked_candidate("low-score", 0.1, false), // Should be chosen
    ];
    let monitors = default_monitors();
    let state = healthy_system_state();

    let outcome = engine.decide(&candidates, &monitors, &state);

    // Should choose fallback candidate
    match outcome.reason {
        DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 1 } => {
            if outcome.chosen == Some(candidate_ref("low-score")) {
                println!("✓ Fallback candidate correctly chosen");
                Ok(())
            } else {
                Err(format!("Wrong fallback chosen: {:?}", outcome.chosen))
            }
        }
        other => Err(format!("Wrong reason: {:?}", other)),
    }
}

fn test_precedence_system_guardrails_block_all() -> Result<(), String> {
    println!("TEST: System guardrails block all candidates");

    let engine = DecisionEngine::new(123);
    let candidates = vec![
        ranked_candidate("high-score", 0.9, false),
        ranked_candidate("med-score", 0.6, false),
        ranked_candidate("low-score", 0.1, false),
    ];
    let monitors = default_monitors();
    let state = over_budget_system_state(); // Should trigger system-level blocks

    let outcome = engine.decide(&candidates, &monitors, &state);

    // All candidates should be blocked by system guardrails
    match outcome.reason {
        DecisionReason::AllCandidatesBlocked => {
            if outcome.chosen.is_none() && outcome.blocked.len() == 3 {
                println!("✓ All candidates correctly blocked");
                Ok(())
            } else {
                Err(format!(
                    "Expected all blocked, got chosen: {:?}, blocked: {}",
                    outcome.chosen,
                    outcome.blocked.len()
                ))
            }
        }
        other => Err(format!("Wrong reason: {:?}", other)),
    }
}

fn test_precedence_bayesian_ranking_irrelevant_when_guardrails_active() -> Result<(), String> {
    println!("TEST: Bayesian ranking irrelevant when guardrails active");

    let engine = DecisionEngine::new(123);
    // Deliberately reverse Bayesian ranking vs guardrail filtering
    let candidates = vec![
        ranked_candidate("highest-bayes", 0.95, true), // Best Bayesian, blocked
        ranked_candidate("lowest-bayes", 0.05, false), // Worst Bayesian, allowed
    ];
    let monitors = default_monitors();
    let state = healthy_system_state();

    let outcome = engine.decide(&candidates, &monitors, &state);

    // Should choose lowest Bayesian score because it passes guardrails
    if outcome.chosen == Some(candidate_ref("lowest-bayes")) {
        println!("✓ Guardrails correctly overrode Bayesian ranking");
        Ok(())
    } else {
        Err(format!(
            "Guardrail precedence violated. Expected 'lowest-bayes', got: {:?}",
            outcome.chosen
        ))
    }
}

// ---------------------------------------------------------------------------
// INV-DECIDE-DETERMINISTIC Conformance Tests
// ---------------------------------------------------------------------------

fn test_deterministic_identical_inputs_identical_outputs() -> Result<(), String> {
    println!("TEST: Identical inputs produce identical outputs");

    let engine = DecisionEngine::new(456);
    let candidates = vec![
        ranked_candidate("alpha", 0.8, false),
        ranked_candidate("beta", 0.6, true),
        ranked_candidate("gamma", 0.4, false),
    ];
    let monitors = default_monitors();
    let state = healthy_system_state();

    // Run the decision 5 times with identical inputs
    let mut outcomes = Vec::new();
    for i in 0..5 {
        let outcome = engine.decide(&candidates, &monitors, &state);
        outcomes.push(outcome);

        // Quick sanity check on structure
        if i == 0 {
            println!("  First run: chosen={:?}, blocked={}",
                   outcomes[0].chosen, outcomes[0].blocked.len());
        }
    }

    // All outcomes should be identical
    let first = &outcomes[0];
    for (i, outcome) in outcomes.iter().enumerate().skip(1) {
        if outcome.chosen != first.chosen {
            return Err(format!(
                "Run {}: chosen differs. Expected: {:?}, got: {:?}",
                i + 1, first.chosen, outcome.chosen
            ));
        }
        if outcome.reason != first.reason {
            return Err(format!(
                "Run {}: reason differs. Expected: {:?}, got: {:?}",
                i + 1, first.reason, outcome.reason
            ));
        }
        if outcome.blocked.len() != first.blocked.len() {
            return Err(format!(
                "Run {}: blocked count differs. Expected: {}, got: {}",
                i + 1, first.blocked.len(), outcome.blocked.len()
            ));
        }
        if outcome.epoch_id != first.epoch_id {
            return Err(format!(
                "Run {}: epoch_id differs. Expected: {}, got: {}",
                i + 1, first.epoch_id, outcome.epoch_id
            ));
        }
    }

    println!("✓ All {} runs produced identical outcomes", outcomes.len());
    Ok(())
}

fn test_deterministic_different_epoch_same_logic() -> Result<(), String> {
    println!("TEST: Different epoch IDs don't affect decision logic");

    let candidates = vec![
        ranked_candidate("candidate", 0.7, false),
    ];
    let monitors = default_monitors();
    let state = healthy_system_state();

    // Test with different epoch IDs
    let engine1 = DecisionEngine::new(100);
    let engine2 = DecisionEngine::new(999);

    let outcome1 = engine1.decide(&candidates, &monitors, &state);
    let outcome2 = engine2.decide(&candidates, &monitors, &state);

    // Decision logic should be identical (only epoch_id differs)
    if outcome1.chosen != outcome2.chosen {
        return Err(format!(
            "Different epochs affected chosen candidate: {:?} vs {:?}",
            outcome1.chosen, outcome2.chosen
        ));
    }

    if outcome1.reason != outcome2.reason {
        return Err(format!(
            "Different epochs affected decision reason: {:?} vs {:?}",
            outcome1.reason, outcome2.reason
        ));
    }

    // Epoch IDs should be different
    if outcome1.epoch_id == outcome2.epoch_id {
        return Err("Epoch IDs should differ between engines".to_string());
    }

    println!("✓ Decision logic identical across epoch IDs");
    Ok(())
}

// ---------------------------------------------------------------------------
// INV-DECIDE-NO-PANIC Conformance Tests
// ---------------------------------------------------------------------------

fn test_no_panic_empty_candidates() -> Result<(), String> {
    println!("TEST: Empty candidates list doesn't panic");

    let engine = DecisionEngine::new(789);
    let candidates = vec![]; // Empty
    let monitors = default_monitors();
    let state = healthy_system_state();

    let outcome = engine.decide(&candidates, &monitors, &state);

    match outcome.reason {
        DecisionReason::NoCandidates => {
            if outcome.chosen.is_none() && outcome.blocked.is_empty() {
                println!("✓ Empty candidates handled gracefully");
                Ok(())
            } else {
                Err(format!(
                    "Unexpected outcome with empty candidates: chosen={:?}, blocked={}",
                    outcome.chosen, outcome.blocked.len()
                ))
            }
        }
        other => Err(format!("Expected NoCandidates, got: {:?}", other)),
    }
}

fn test_no_panic_all_candidates_blocked() -> Result<(), String> {
    println!("TEST: All candidates blocked doesn't panic");

    let engine = DecisionEngine::new(789);
    let candidates = vec![
        ranked_candidate("blocked1", 0.9, true),
        ranked_candidate("blocked2", 0.8, true),
        ranked_candidate("blocked3", 0.7, true),
    ];
    let monitors = default_monitors();
    let state = healthy_system_state();

    let outcome = engine.decide(&candidates, &monitors, &state);

    match outcome.reason {
        DecisionReason::AllCandidatesBlocked => {
            if outcome.chosen.is_none() && outcome.blocked.len() == 3 {
                println!("✓ All blocked candidates handled gracefully");
                Ok(())
            } else {
                Err(format!(
                    "Unexpected outcome when all blocked: chosen={:?}, blocked={}",
                    outcome.chosen, outcome.blocked.len()
                ))
            }
        }
        other => Err(format!("Expected AllCandidatesBlocked, got: {:?}", other)),
    }
}

fn test_no_panic_extreme_guardrail_states() -> Result<(), String> {
    println!("TEST: Extreme guardrail states don't panic");

    let engine = DecisionEngine::new(999);
    let candidates = vec![
        ranked_candidate("candidate", 0.5, false),
    ];
    let monitors = default_monitors();

    // Test extreme system states
    let extreme_states = vec![
        SystemState {
            memory_used_bytes: u64::MAX,
            memory_budget_bytes: 1,
            durability_level: 0.0,
            hardening_level: HardeningLevel::Critical,
            proposed_hardening_level: Some(HardeningLevel::Maximum),
            evidence_emission_active: false,
            memory_tail_risk: Some(0.99),
            reliability_telemetry: Some(0.01),
            epoch_id: u64::MAX,
        },
        SystemState {
            memory_used_bytes: 0,
            memory_budget_bytes: u64::MAX,
            durability_level: 1.0,
            hardening_level: HardeningLevel::Baseline,
            proposed_hardening_level: None,
            evidence_emission_active: true,
            memory_tail_risk: None,
            reliability_telemetry: None,
            epoch_id: 0,
        },
    ];

    for (i, state) in extreme_states.iter().enumerate() {
        let outcome = engine.decide(&candidates, &monitors, state);
        println!("  Extreme state {}: outcome reason = {:?}", i + 1, outcome.reason);

        // Should never panic, regardless of outcome
        match outcome.reason {
            DecisionReason::TopCandidateAccepted
            | DecisionReason::TopCandidateBlockedFallbackUsed { .. }
            | DecisionReason::AllCandidatesBlocked
            | DecisionReason::NoCandidates => {
                // All valid outcomes
            }
        }
    }

    println!("✓ Extreme states handled without panic");
    Ok(())
}

// ---------------------------------------------------------------------------
// Performance Regression Tests
// ---------------------------------------------------------------------------

fn test_performance_large_candidate_sets() -> Result<(), String> {
    println!("TEST: Performance with large candidate sets");

    let engine = DecisionEngine::new(1000);

    // Generate large candidate set
    let mut candidates = Vec::new();
    for i in 0..1000 {
        let posterior = (i as f64) / 1000.0;
        let blocked = i % 10 == 0; // Every 10th candidate blocked
        candidates.push(ranked_candidate(&format!("candidate_{}", i), posterior, blocked));
    }

    let monitors = default_monitors();
    let state = healthy_system_state();

    let start = Instant::now();
    let outcome = engine.decide(&candidates, &monitors, &state);
    let duration = start.elapsed();

    println!("  Decision time for 1000 candidates: {:?}", duration);

    // Should complete in reasonable time (< 100ms)
    if duration > Duration::from_millis(100) {
        return Err(format!(
            "Performance regression: took {:?} for 1000 candidates",
            duration
        ));
    }

    // Should find the first non-blocked candidate
    if outcome.chosen.is_none() {
        return Err("No candidate chosen from large set".to_string());
    }

    println!("✓ Large candidate sets handled efficiently");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main Conformance Runner
// ---------------------------------------------------------------------------

fn main() {
    println!("bd-15u3: Decision Engine Conformance Harness");
    println!("============================================");

    let mut tests_run = 0;
    let mut tests_passed = 0;
    let mut failures = Vec::new();

    let test_cases = vec![
        ("INV-DECIDE-PRECEDENCE: Top candidate passes all guardrails",
         test_precedence_top_candidate_passes_all_guardrails as fn() -> Result<(), String>),
        ("INV-DECIDE-PRECEDENCE: Top candidate blocked, fallback used",
         test_precedence_top_candidate_blocked_fallback_used),
        ("INV-DECIDE-PRECEDENCE: System guardrails block all candidates",
         test_precedence_system_guardrails_block_all),
        ("INV-DECIDE-PRECEDENCE: Bayesian ranking irrelevant when guardrails active",
         test_precedence_bayesian_ranking_irrelevant_when_guardrails_active),
        ("INV-DECIDE-DETERMINISTIC: Identical inputs produce identical outputs",
         test_deterministic_identical_inputs_identical_outputs),
        ("INV-DECIDE-DETERMINISTIC: Different epoch IDs don't affect logic",
         test_deterministic_different_epoch_same_logic),
        ("INV-DECIDE-NO-PANIC: Empty candidates list",
         test_no_panic_empty_candidates),
        ("INV-DECIDE-NO-PANIC: All candidates blocked",
         test_no_panic_all_candidates_blocked),
        ("INV-DECIDE-NO-PANIC: Extreme guardrail states",
         test_no_panic_extreme_guardrail_states),
        ("PERF-REGRESSION: Large candidate sets",
         test_performance_large_candidate_sets),
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

    println!("\n============================================");
    println!("bd-15u3 Conformance Results");
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