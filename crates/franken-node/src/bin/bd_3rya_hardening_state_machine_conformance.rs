#!/usr/bin/env cargo
//! bd-3rya: Monotonic hardening state machine conformance harness.
//!
//! Tests INV-HARDEN-MONOTONIC, INV-HARDEN-DURABLE, INV-HARDEN-AUDITABLE,
//! and INV-HARDEN-GOVERNANCE to ensure one-way escalation with auditable
//! governance rollback capability operates correctly in all scenarios.

use std::time::{Duration, Instant};

use frankenengine_node::policy::hardening_state_machine::{
    GovernanceRollbackArtifact, HardeningError, HardeningLevel, HardeningStateMachine,
    TransitionRecord, TransitionTrigger,
};

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

fn trace_id(n: u32) -> String {
    format!("conformance-trace-{:04}", n)
}

fn valid_governance_artifact(id: &str) -> GovernanceRollbackArtifact {
    GovernanceRollbackArtifact {
        artifact_id: id.to_string(),
        approver_id: "admin@franken.io".to_string(),
        reason: "Conformance test authorized rollback".to_string(),
        timestamp: 2000,
        signature: "sig:valid_signature_hash".to_string(),
    }
}

fn invalid_governance_artifact_empty_fields() -> GovernanceRollbackArtifact {
    GovernanceRollbackArtifact {
        artifact_id: "".to_string(),  // Invalid: empty
        approver_id: "".to_string(),  // Invalid: empty
        reason: "".to_string(),       // Invalid: empty
        timestamp: 2000,
        signature: "".to_string(),    // Invalid: empty
    }
}

fn invalid_governance_artifact_reserved_id() -> GovernanceRollbackArtifact {
    GovernanceRollbackArtifact {
        artifact_id: "<unknown>".to_string(),  // Invalid: reserved
        approver_id: "admin@franken.io".to_string(),
        reason: "Test rollback".to_string(),
        timestamp: 2000,
        signature: "sig:valid".to_string(),
    }
}

// ---------------------------------------------------------------------------
// INV-HARDEN-MONOTONIC Conformance Tests
// ---------------------------------------------------------------------------

fn test_monotonic_escalation_sequence() -> Result<(), String> {
    println!("TEST: Monotonic escalation through all levels");

    let mut machine = HardeningStateMachine::new();

    // Start at Baseline
    assert_eq!(machine.current_level(), HardeningLevel::Baseline);

    let levels = [
        HardeningLevel::Standard,
        HardeningLevel::Enhanced,
        HardeningLevel::Maximum,
        HardeningLevel::Critical,
    ];

    let mut timestamp = 1000u64;

    for (i, &target_level) in levels.iter().enumerate() {
        timestamp += 1000;
        let result = machine.escalate(target_level, timestamp, &trace_id(i as u32));

        match result {
            Ok(record) => {
                if machine.current_level() != target_level {
                    return Err(format!(
                        "Level {} escalation failed: current level {:?} != expected {:?}",
                        i + 1, machine.current_level(), target_level
                    ));
                }

                if record.to_level != target_level {
                    return Err(format!(
                        "Level {} escalation record incorrect: {:?} != {:?}",
                        i + 1, record.to_level, target_level
                    ));
                }

                println!("  ✓ Escalated to {}", target_level);
            }
            Err(err) => {
                return Err(format!(
                    "Level {} escalation failed unexpectedly: {:?}",
                    i + 1, err
                ));
            }
        }
    }

    println!("✓ Monotonic escalation sequence successful");
    Ok(())
}

fn test_monotonic_regression_rejected() -> Result<(), String> {
    println!("TEST: Regression attempts correctly rejected");

    let mut machine = HardeningStateMachine::with_level(HardeningLevel::Enhanced);

    let invalid_targets = [
        (HardeningLevel::Enhanced, "same level"),
        (HardeningLevel::Standard, "downgrade to Standard"),
        (HardeningLevel::Baseline, "downgrade to Baseline"),
    ];

    for (target, description) in invalid_targets.iter() {
        let result = machine.escalate(*target, 2000, &trace_id(0));

        match result {
            Err(HardeningError::IllegalRegression { current, attempted }) => {
                if current != HardeningLevel::Enhanced || attempted != *target {
                    return Err(format!(
                        "Incorrect regression error for {}: got current={:?}, attempted={:?}",
                        description, current, attempted
                    ));
                }
                println!("  ✓ {} correctly rejected", description);
            }
            Ok(_) => {
                return Err(format!(
                    "Regression should have been rejected: {}",
                    description
                ));
            }
            Err(other) => {
                return Err(format!(
                    "Unexpected error type for {}: {:?}",
                    description, other
                ));
            }
        }
    }

    // Verify current level unchanged
    if machine.current_level() != HardeningLevel::Enhanced {
        return Err(format!(
            "Current level changed after rejected regressions: {:?}",
            machine.current_level()
        ));
    }

    println!("✓ All regression attempts correctly rejected");
    Ok(())
}

fn test_monotonic_maximum_level_handling() -> Result<(), String> {
    println!("TEST: Maximum level edge case handling");

    let mut machine = HardeningStateMachine::with_level(HardeningLevel::Critical);

    // Cannot escalate beyond Critical
    let result = machine.escalate(HardeningLevel::Critical, 3000, &trace_id(0));

    match result {
        Err(HardeningError::IllegalRegression { current, attempted }) => {
            if current == HardeningLevel::Critical && attempted == HardeningLevel::Critical {
                println!("  ✓ Same-level escalation at maximum correctly rejected");
                Ok(())
            } else {
                Err(format!(
                    "Incorrect regression error at maximum: current={:?}, attempted={:?}",
                    current, attempted
                ))
            }
        }
        Ok(_) => Err("Same-level escalation at Critical should be rejected".to_string()),
        Err(other) => Err(format!(
            "Unexpected error type at maximum level: {:?}",
            other
        )),
    }
}

// ---------------------------------------------------------------------------
// INV-HARDEN-GOVERNANCE Conformance Tests
// ---------------------------------------------------------------------------

fn test_governance_valid_rollback() -> Result<(), String> {
    println!("TEST: Valid governance rollback authorizes downgrade");

    let mut machine = HardeningStateMachine::with_level(HardeningLevel::Maximum);
    let artifact = valid_governance_artifact("GOV-CONF-001");

    let result = machine.governance_rollback(
        HardeningLevel::Standard,
        &artifact,
        4000,
        &trace_id(1),
    );

    match result {
        Ok(record) => {
            if machine.current_level() != HardeningLevel::Standard {
                return Err(format!(
                    "Rollback failed: current level {:?} != expected Standard",
                    machine.current_level()
                ));
            }

            if record.from_level != HardeningLevel::Maximum
                || record.to_level != HardeningLevel::Standard {
                return Err(format!(
                    "Rollback record incorrect: from={:?}, to={:?}",
                    record.from_level, record.to_level
                ));
            }

            match &record.trigger {
                TransitionTrigger::GovernanceRollback { artifact_id, approver_id } => {
                    if artifact_id != "GOV-CONF-001" || approver_id != "admin@franken.io" {
                        return Err(format!(
                            "Rollback trigger data incorrect: artifact_id={}, approver_id={}",
                            artifact_id, approver_id
                        ));
                    }
                }
                other => {
                    return Err(format!(
                        "Expected GovernanceRollback trigger, got: {:?}",
                        other
                    ));
                }
            }

            println!("✓ Valid governance rollback authorized and recorded");
            Ok(())
        }
        Err(err) => Err(format!(
            "Valid governance rollback should have succeeded: {:?}",
            err
        )),
    }
}

fn test_governance_invalid_artifact_rejected() -> Result<(), String> {
    println!("TEST: Invalid governance artifacts correctly rejected");

    let mut machine = HardeningStateMachine::with_level(HardeningLevel::Enhanced);

    let test_cases = [
        (invalid_governance_artifact_empty_fields(), "empty fields"),
        (invalid_governance_artifact_reserved_id(), "reserved artifact ID"),
    ];

    for (artifact, description) in test_cases.iter() {
        let result = machine.governance_rollback(
            HardeningLevel::Baseline,
            artifact,
            5000,
            &trace_id(2),
        );

        match result {
            Err(HardeningError::InvalidRollbackArtifact { reason }) => {
                if !reason.is_empty() {
                    println!("  ✓ {} correctly rejected: {}", description, reason);
                } else {
                    return Err(format!(
                        "Invalid artifact rejection should have reason: {}",
                        description
                    ));
                }
            }
            Ok(_) => {
                return Err(format!(
                    "Invalid governance artifact should have been rejected: {}",
                    description
                ));
            }
            Err(other) => {
                return Err(format!(
                    "Unexpected error type for {}: {:?}",
                    description, other
                ));
            }
        }

        // Verify level unchanged after rejection
        if machine.current_level() != HardeningLevel::Enhanced {
            return Err(format!(
                "Level changed after artifact rejection: {:?}",
                machine.current_level()
            ));
        }
    }

    println!("✓ All invalid governance artifacts correctly rejected");
    Ok(())
}

fn test_governance_invalid_target_rejected() -> Result<(), String> {
    println!("TEST: Invalid rollback targets correctly rejected");

    let mut machine = HardeningStateMachine::with_level(HardeningLevel::Standard);
    let valid_artifact = valid_governance_artifact("GOV-CONF-002");

    let invalid_targets = [
        (HardeningLevel::Standard, "same level"),
        (HardeningLevel::Enhanced, "higher level"),
        (HardeningLevel::Critical, "much higher level"),
    ];

    for (target, description) in invalid_targets.iter() {
        let result = machine.governance_rollback(
            *target,
            &valid_artifact,
            6000,
            &trace_id(3),
        );

        match result {
            Err(HardeningError::InvalidRollbackTarget { current, target: attempted }) => {
                if current != HardeningLevel::Standard || attempted != *target {
                    return Err(format!(
                        "Incorrect rollback target error for {}: current={:?}, target={:?}",
                        description, current, attempted
                    ));
                }
                println!("  ✓ {} correctly rejected", description);
            }
            Ok(_) => {
                return Err(format!(
                    "Invalid rollback target should have been rejected: {}",
                    description
                ));
            }
            Err(other) => {
                return Err(format!(
                    "Unexpected error type for {}: {:?}",
                    description, other
                ));
            }
        }

        // Verify level unchanged
        if machine.current_level() != HardeningLevel::Standard {
            return Err(format!(
                "Level changed after target rejection: {:?}",
                machine.current_level()
            ));
        }
    }

    println!("✓ All invalid rollback targets correctly rejected");
    Ok(())
}

// ---------------------------------------------------------------------------
// INV-HARDEN-AUDITABLE Conformance Tests
// ---------------------------------------------------------------------------

fn test_auditable_transition_recording() -> Result<(), String> {
    println!("TEST: All transitions properly recorded in audit log");

    let mut machine = HardeningStateMachine::new();

    // Perform sequence of escalations
    let _ = machine.escalate(HardeningLevel::Standard, 1000, &trace_id(100));
    let _ = machine.escalate(HardeningLevel::Enhanced, 2000, &trace_id(200));

    // Perform governance rollback
    let artifact = valid_governance_artifact("GOV-AUDIT-001");
    let _ = machine.governance_rollback(
        HardeningLevel::Baseline,
        &artifact,
        3000,
        &trace_id(300),
    );

    // Another escalation
    let _ = machine.escalate(HardeningLevel::Maximum, 4000, &trace_id(400));

    let log = machine.transition_log();

    if log.len() != 4 {
        return Err(format!(
            "Expected 4 transition records, got {}",
            log.len()
        ));
    }

    // Check first escalation record
    let record1 = &log[0];
    if record1.from_level != HardeningLevel::Baseline
        || record1.to_level != HardeningLevel::Standard
        || record1.timestamp != 1000
        || record1.trace_id != trace_id(100) {
        return Err(format!(
            "First transition record incorrect: {:?}",
            record1
        ));
    }

    if !matches!(record1.trigger, TransitionTrigger::Escalation) {
        return Err(format!(
            "First transition should be Escalation trigger: {:?}",
            record1.trigger
        ));
    }

    // Check governance rollback record
    let record3 = &log[2];
    if record3.from_level != HardeningLevel::Enhanced
        || record3.to_level != HardeningLevel::Baseline
        || record3.timestamp != 3000 {
        return Err(format!(
            "Rollback transition record incorrect: {:?}",
            record3
        ));
    }

    match &record3.trigger {
        TransitionTrigger::GovernanceRollback { artifact_id, approver_id } => {
            if artifact_id != "GOV-AUDIT-001" || approver_id != "admin@franken.io" {
                return Err(format!(
                    "Rollback trigger data incorrect: artifact_id={}, approver_id={}",
                    artifact_id, approver_id
                ));
            }
        }
        other => {
            return Err(format!(
                "Expected GovernanceRollback trigger, got: {:?}",
                other
            ));
        }
    }

    println!("✓ All transitions properly recorded with correct metadata");
    Ok(())
}

fn test_auditable_timestamp_sequence() -> Result<(), String> {
    println!("TEST: Audit log preserves timestamp sequence");

    let mut machine = HardeningStateMachine::new();

    let timestamps = [1000u64, 1500, 2200, 3100, 4000];
    let mut expected_from = HardeningLevel::Baseline;

    for (i, &timestamp) in timestamps.iter().enumerate() {
        let target = match i {
            0 => HardeningLevel::Standard,
            1 => HardeningLevel::Enhanced,
            2 => HardeningLevel::Maximum,
            3 => HardeningLevel::Critical,
            4 => HardeningLevel::Standard, // Governance rollback
            _ => unreachable!(),
        };

        if i == 4 {
            // Governance rollback case
            let artifact = valid_governance_artifact("GOV-TS-001");
            let _ = machine.governance_rollback(target, &artifact, timestamp, &trace_id(i as u32));
        } else {
            let _ = machine.escalate(target, timestamp, &trace_id(i as u32));
        }

        expected_from = target;
    }

    let log = machine.transition_log();

    // Verify timestamps are preserved in order
    for (i, record) in log.iter().enumerate() {
        if record.timestamp != timestamps[i] {
            return Err(format!(
                "Timestamp {} incorrect: expected {}, got {}",
                i, timestamps[i], record.timestamp
            ));
        }
    }

    println!("✓ Timestamp sequence preserved in audit log");
    Ok(())
}

// ---------------------------------------------------------------------------
// INV-HARDEN-DURABLE Conformance Tests
// ---------------------------------------------------------------------------

fn test_durable_replay_identical_state() -> Result<(), String> {
    println!("TEST: State replay produces identical machine state");

    // Build original machine with transitions
    let mut original = HardeningStateMachine::new();

    let _ = original.escalate(HardeningLevel::Standard, 1000, &trace_id(1));
    let _ = original.escalate(HardeningLevel::Enhanced, 2000, &trace_id(2));

    let artifact = valid_governance_artifact("GOV-REPLAY-001");
    let _ = original.governance_rollback(
        HardeningLevel::Baseline,
        &artifact,
        3000,
        &trace_id(3),
    );

    let _ = original.escalate(HardeningLevel::Maximum, 4000, &trace_id(4));

    // Capture state and log
    let original_level = original.current_level();
    let original_log = original.transition_log().to_vec();

    // Replay from log
    let replayed = HardeningStateMachine::replay_transitions(&original_log);

    // Verify identical state
    if replayed.current_level() != original_level {
        return Err(format!(
            "Replayed level {:?} != original level {:?}",
            replayed.current_level(), original_level
        ));
    }

    let replayed_log = replayed.transition_log();
    if replayed_log.len() != original_log.len() {
        return Err(format!(
            "Replayed log length {} != original log length {}",
            replayed_log.len(), original_log.len()
        ));
    }

    for (i, (original_record, replayed_record)) in
        original_log.iter().zip(replayed_log.iter()).enumerate() {
        if original_record != replayed_record {
            return Err(format!(
                "Transition record {} differs after replay:\nOriginal: {:?}\nReplayed: {:?}",
                i, original_record, replayed_record
            ));
        }
    }

    println!("✓ State replay produces identical machine state");
    Ok(())
}

fn test_durable_replay_corrupted_log_resilience() -> Result<(), String> {
    println!("TEST: Replay resilient to corrupted log entries");

    // Build valid log
    let mut machine = HardeningStateMachine::new();
    let _ = machine.escalate(HardeningLevel::Standard, 1000, &trace_id(1));
    let _ = machine.escalate(HardeningLevel::Enhanced, 2000, &trace_id(2));

    let mut log = machine.transition_log().to_vec();

    // Inject corruption: invalid transition (downgrade without governance)
    let corrupted_record = TransitionRecord {
        from_level: HardeningLevel::Enhanced,
        to_level: HardeningLevel::Baseline,  // Invalid: downgrade without governance
        timestamp: 2500,
        trigger: TransitionTrigger::Escalation,  // Invalid: escalation can't downgrade
        trace_id: "corrupted".to_string(),
    };
    log.push(corrupted_record);

    // Add valid record after corruption
    let valid_record = TransitionRecord {
        from_level: HardeningLevel::Enhanced,  // Should resume from pre-corruption state
        to_level: HardeningLevel::Maximum,
        timestamp: 3000,
        trigger: TransitionTrigger::Escalation,
        trace_id: trace_id(3),
    };
    log.push(valid_record);

    // Replay should skip corrupted entry and continue with valid ones
    let replayed = HardeningStateMachine::replay_transitions(&log);

    if replayed.current_level() != HardeningLevel::Maximum {
        return Err(format!(
            "Replay should reach Maximum despite corruption, got: {:?}",
            replayed.current_level()
        ));
    }

    // Log should contain only valid transitions (original 2 + final 1)
    let replayed_log = replayed.transition_log();
    if replayed_log.len() != 3 {
        return Err(format!(
            "Replayed log should have 3 valid entries, got {}",
            replayed_log.len()
        ));
    }

    println!("✓ Replay resilient to corrupted log entries");
    Ok(())
}

fn test_durable_replay_empty_log() -> Result<(), String> {
    println!("TEST: Replay with empty log creates baseline machine");

    let empty_log: Vec<TransitionRecord> = Vec::new();
    let replayed = HardeningStateMachine::replay_transitions(&empty_log);

    if replayed.current_level() != HardeningLevel::Baseline {
        return Err(format!(
            "Empty log replay should create Baseline machine, got: {:?}",
            replayed.current_level()
        ));
    }

    if replayed.transition_count() != 0 {
        return Err(format!(
            "Empty log replay should have empty transition log, got {} entries",
            replayed.transition_count()
        ));
    }

    println!("✓ Empty log replay creates proper baseline machine");
    Ok(())
}

// ---------------------------------------------------------------------------
// Performance and Edge Case Tests
// ---------------------------------------------------------------------------

fn test_performance_large_transition_log() -> Result<(), String> {
    println!("TEST: Performance with large transition history");

    let mut machine = HardeningStateMachine::new();

    let start = Instant::now();

    // Create many transitions by cycling through levels with governance
    for i in 0..1000 {
        let timestamp = 1000 + i;

        if i % 2 == 0 {
            // Escalate to Standard
            let _ = machine.escalate(HardeningLevel::Standard, timestamp, &trace_id(i as u32));
        } else {
            // Roll back to Baseline
            let artifact = valid_governance_artifact(&format!("GOV-PERF-{}", i));
            let _ = machine.governance_rollback(
                HardeningLevel::Baseline,
                &artifact,
                timestamp,
                &trace_id(i as u32),
            );
        }
    }

    let duration = start.elapsed();

    if machine.transition_count() > 4096 {
        return Err(format!(
            "Transition log exceeded maximum capacity: {} > 4096",
            machine.transition_count()
        ));
    }

    println!("  Performance: 1000 transitions in {:?}", duration);

    if duration > Duration::from_millis(100) {
        return Err(format!(
            "Performance regression: took {:?} for 1000 transitions",
            duration
        ));
    }

    println!("✓ Large transition history handled efficiently");
    Ok(())
}

fn test_edge_cases_all_level_combinations() -> Result<(), String> {
    println!("TEST: All valid level transition combinations");

    let levels = [
        HardeningLevel::Baseline,
        HardeningLevel::Standard,
        HardeningLevel::Enhanced,
        HardeningLevel::Maximum,
        HardeningLevel::Critical,
    ];

    for (i, &from_level) in levels.iter().enumerate() {
        for (j, &to_level) in levels.iter().enumerate() {
            let mut machine = HardeningStateMachine::with_level(from_level);

            if j > i {
                // Valid escalation
                let result = machine.escalate(to_level, 5000, &trace_id(0));
                if result.is_err() {
                    return Err(format!(
                        "Valid escalation {} -> {} failed: {:?}",
                        from_level, to_level, result.unwrap_err()
                    ));
                }
            } else if j < i {
                // Valid governance rollback
                let artifact = valid_governance_artifact("GOV-EDGE-001");
                let result = machine.governance_rollback(to_level, &artifact, 5000, &trace_id(0));
                if result.is_err() {
                    return Err(format!(
                        "Valid rollback {} -> {} failed: {:?}",
                        from_level, to_level, result.unwrap_err()
                    ));
                }
            } else {
                // Same level - should be rejected
                let result = machine.escalate(to_level, 5000, &trace_id(0));
                if result.is_ok() {
                    return Err(format!(
                        "Same-level transition {} -> {} should have been rejected",
                        from_level, to_level
                    ));
                }
            }
        }
    }

    println!("✓ All level transition combinations behave correctly");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main Conformance Runner
// ---------------------------------------------------------------------------

fn main() {
    println!("bd-3rya: Hardening State Machine Conformance Harness");
    println!("===================================================");

    let mut tests_run = 0;
    let mut tests_passed = 0;
    let mut failures = Vec::new();

    let test_cases = vec![
        ("INV-HARDEN-MONOTONIC: Escalation sequence through all levels", test_monotonic_escalation_sequence as fn() -> Result<(), String>),
        ("INV-HARDEN-MONOTONIC: Regression attempts correctly rejected", test_monotonic_regression_rejected),
        ("INV-HARDEN-MONOTONIC: Maximum level edge case handling", test_monotonic_maximum_level_handling),
        ("INV-HARDEN-GOVERNANCE: Valid governance rollback authorizes downgrade", test_governance_valid_rollback),
        ("INV-HARDEN-GOVERNANCE: Invalid artifacts correctly rejected", test_governance_invalid_artifact_rejected),
        ("INV-HARDEN-GOVERNANCE: Invalid targets correctly rejected", test_governance_invalid_target_rejected),
        ("INV-HARDEN-AUDITABLE: Transition recording in audit log", test_auditable_transition_recording),
        ("INV-HARDEN-AUDITABLE: Timestamp sequence preservation", test_auditable_timestamp_sequence),
        ("INV-HARDEN-DURABLE: Replay produces identical state", test_durable_replay_identical_state),
        ("INV-HARDEN-DURABLE: Replay resilient to corrupted entries", test_durable_replay_corrupted_log_resilience),
        ("INV-HARDEN-DURABLE: Empty log replay creates baseline", test_durable_replay_empty_log),
        ("PERF-REGRESSION: Large transition history performance", test_performance_large_transition_log),
        ("EDGE-CASE: All valid level transition combinations", test_edge_cases_all_level_combinations),
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
    println!("bd-3rya Conformance Results");
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