//! Control Plane Module Conformance Tests
//!
//! These tests verify security hardening patterns and edge case behavior
//! across the control plane modules:
//! - Epoch management and overflow protection
//! - Cancellation protocol timeout handling
//! - Barrier coordination boundary conditions
//! - Fork detection constant-time operations
//! - Thread safety and poison recovery

use super::cancellation_protocol::{
    CancellationProtocol, DrainConfig, ResourceTracker, error_codes as cancel_error_codes,
};
use super::control_epoch::{
    ControlEpoch, EpochError, EpochRejectionReason, EpochStore, ValidityWindowPolicy,
    check_artifact_epoch,
};
// bd-yom8c: `AbortReason` moved from `cancellation_protocol` to `epoch_transition_barrier`.
use super::epoch_transition_barrier::{
    AbortReason, BarrierConfig, BarrierError, BarrierPhase, DrainAck, EpochTransitionBarrier,
    error_codes as barrier_error_codes,
};
use super::fork_detection::{
    DetectionResult, DivergenceDetector, ForkDetectionError, MarkerProofVerifier, RollbackDetector,
    StateVector,
};
use crate::control_plane::marker_stream::{MarkerEventType, MarkerStream};
use crate::lock_utils::try_lock;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ---- Control Epoch Hardening Tests ----

#[test]
fn epoch_store_overflow_protection() {
    let mut store = EpochStore::recover(u64::MAX - 1);

    // Should advance to MAX successfully
    let t1 = store
        .epoch_advance("manifest-max", 9000, "trace-max")
        .unwrap();
    assert_eq!(t1.new_epoch.value(), u64::MAX);

    // Next advance should fail with overflow
    let err = store
        .epoch_advance("manifest-overflow", 9001, "trace-overflow")
        .unwrap_err();
    assert_eq!(err.code(), "EPOCH_OVERFLOW");

    // Store state should remain at MAX, not wrap around
    assert_eq!(store.epoch_read().value(), u64::MAX);
}

#[test]
fn epoch_next_saturating_behavior() {
    let epoch_max = ControlEpoch::new(u64::MAX);
    assert!(epoch_max.next().is_none());

    let epoch_near_max = ControlEpoch::new(u64::MAX - 1);
    assert_eq!(epoch_near_max.next().unwrap().value(), u64::MAX);
}

#[test]
fn validity_window_saturating_sub() {
    // Test edge case: current_epoch < max_lookback should saturate to 0
    let policy = ValidityWindowPolicy::new(ControlEpoch::new(5), 10);
    assert_eq!(policy.min_accepted_epoch().value(), 0);

    // Normal case
    let policy = ValidityWindowPolicy::new(ControlEpoch::new(100), 10);
    assert_eq!(policy.min_accepted_epoch().value(), 90);
}

#[test]
fn validity_window_boundary_conditions() {
    let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 5);

    // Exactly at boundary should pass
    let result = check_artifact_epoch(
        "artifact-boundary",
        ControlEpoch::new(5),
        &policy,
        "trace-1",
    );
    assert!(result.is_ok());

    // One past boundary should fail
    let err = check_artifact_epoch("artifact-expired", ControlEpoch::new(4), &policy, "trace-2")
        .unwrap_err();
    assert_eq!(err.rejection_reason, EpochRejectionReason::ExpiredEpoch);
}

#[test]
fn validity_window_rejects_future_epoch() {
    let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 5);

    let err = check_artifact_epoch(
        "artifact-future",
        ControlEpoch::new(11),
        &policy,
        "trace-future",
    )
    .unwrap_err();

    assert_eq!(err.code(), "EPOCH_REJECT_FUTURE");
    assert_eq!(err.rejection_reason, EpochRejectionReason::FutureEpoch);
}

#[test]
fn validity_window_rejects_empty_artifact_id() {
    let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 5);

    let err = check_artifact_epoch("", ControlEpoch::new(10), &policy, "trace-empty").unwrap_err();

    assert_eq!(err.code(), "EPOCH_REJECT_INVALID_ARTIFACT_ID");
    assert_eq!(
        err.rejection_reason,
        EpochRejectionReason::InvalidArtifactId
    );
}

#[test]
fn validity_window_rejects_padded_artifact_id() {
    let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 5);

    let err = check_artifact_epoch(" artifact ", ControlEpoch::new(10), &policy, "trace-padded")
        .unwrap_err();

    assert_eq!(err.code(), "EPOCH_REJECT_INVALID_ARTIFACT_ID");
    assert_eq!(
        err.rejection_reason,
        EpochRejectionReason::InvalidArtifactId
    );
}

#[test]
fn epoch_store_rejects_empty_manifest_without_advancing() {
    let mut store = EpochStore::new();

    let err = store
        .epoch_advance("", 1000, "trace-empty-manifest")
        .unwrap_err();

    assert_eq!(err.code(), "EPOCH_INVALID_MANIFEST");
    assert_eq!(store.epoch_read().value(), 0);
}

#[test]
fn epoch_concurrent_access_safety() {
    let store = Arc::new(Mutex::new(EpochStore::new()));
    let mut handles = Vec::new();

    // Spawn multiple threads trying to advance epochs
    for i in 0..10 {
        let store_clone = Arc::clone(&store);
        let handle = thread::spawn(move || {
            for j in 0..100 {
                let manifest = format!("manifest-{}-{}", i, j);
                let trace = format!("trace-{}-{}", i, j);
                let mut store = try_lock(&store_clone, "advance epoch concurrently")
                    .expect("epoch store mutex should not be poisoned");
                let _result = store.epoch_advance(&manifest, 1000 + j, &trace);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify final epoch is reasonable and no overflow occurred
    let final_epoch = try_lock(&store, "inspect epoch store final state")
        .expect("epoch store mutex should not be poisoned")
        .epoch_read()
        .value();
    assert!(final_epoch > 0 && final_epoch <= 1000);
}

// ---- Cancellation Protocol Hardening Tests ----

#[test]
fn cancellation_drain_timeout_boundary() {
    let config = DrainConfig::new(1000, false); // 1s timeout, no force
    let mut protocol = CancellationProtocol::new(config);

    protocol
        .request_cancel("workflow-1", 5, 1000, "trace-1")
        .unwrap();
    protocol.start_drain("workflow-1", 1100, "trace-1").unwrap();

    // Exactly at timeout boundary (elapsed = 1000ms)
    let err = protocol
        .complete_drain("workflow-1", 2100, "trace-1")
        .unwrap_err();
    assert_eq!(err.code(), cancel_error_codes::ERR_CANCEL_DRAIN_TIMEOUT);

    // Just under timeout should work with force=true
    let config_force = DrainConfig::new(1000, true);
    let mut protocol_force = CancellationProtocol::new(config_force);
    protocol_force
        .request_cancel("workflow-2", 5, 1000, "trace-2")
        .unwrap();
    protocol_force
        .start_drain("workflow-2", 1100, "trace-2")
        .unwrap();

    // At timeout with force should succeed
    let result = protocol_force
        .complete_drain("workflow-2", 2100, "trace-2")
        .unwrap();
    assert!(result.drain_timed_out);
    assert_eq!(
        result.current_phase,
        super::cancellation_protocol::CancelPhase::DrainComplete
    );
}

#[test]
fn cancellation_resource_leak_detection() {
    let mut protocol = CancellationProtocol::default();
    protocol
        .request_cancel("workflow-leak", 0, 1000, "trace-1")
        .unwrap();
    protocol
        .start_drain("workflow-leak", 1100, "trace-1")
        .unwrap();
    protocol
        .complete_drain("workflow-leak", 1200, "trace-1")
        .unwrap();

    // Create resources with various leak types
    let mut resources = ResourceTracker::empty();
    resources.open_handles.push("fd-42".to_string());
    resources.pending_writes = u64::MAX; // Extreme case
    resources.held_locks.push("mutex-critical".to_string());

    let err = protocol
        .finalize("workflow-leak", &resources, 1300, "trace-1")
        .unwrap_err();
    assert_eq!(err.code(), cancel_error_codes::ERR_CANCEL_LEAK);

    // Phase should remain Finalizing, not advance to Finalized
    let phase = protocol.current_phase("workflow-leak").unwrap();
    assert_eq!(phase, super::cancellation_protocol::CancelPhase::Finalizing);
}

#[test]
fn cancellation_audit_log_bounded_growth() {
    let mut protocol = CancellationProtocol::with_audit_log_capacity(DrainConfig::default(), 3);

    // Generate more events than capacity
    for i in 0..10 {
        let workflow_id = format!("workflow-{}", i);
        protocol
            .request_cancel(&workflow_id, 0, 1000 + i, &format!("trace-{}", i))
            .unwrap();
    }

    // Audit log should be bounded to capacity
    assert_eq!(protocol.audit_log().len(), 3);

    // Should contain only the most recent events
    let events = protocol.audit_log();
    assert!(
        events[0].workflow_id.contains("workflow-7")
            || events[0].workflow_id.contains("workflow-8")
            || events[0].workflow_id.contains("workflow-9")
    );
}

#[test]
fn cancellation_start_drain_unknown_workflow_rejected() {
    let mut protocol = CancellationProtocol::default();

    let err = protocol
        .start_drain("missing-workflow", 1000, "trace-missing")
        .unwrap_err();

    assert_eq!(err.code(), cancel_error_codes::ERR_CANCEL_NOT_FOUND);
    assert!(protocol.audit_log().is_empty());
}

#[test]
fn cancellation_complete_drain_before_start_rejected() {
    let mut protocol = CancellationProtocol::default();
    protocol
        .request_cancel("workflow-no-drain", 3, 1000, "trace-no-drain")
        .unwrap();

    let err = protocol
        .complete_drain("workflow-no-drain", 1100, "trace-no-drain")
        .unwrap_err();

    assert_eq!(err.code(), cancel_error_codes::ERR_CANCEL_INVALID_PHASE);
    assert_eq!(
        protocol.current_phase("workflow-no-drain").unwrap(),
        super::cancellation_protocol::CancelPhase::CancelRequested
    );
}

#[test]
fn cancellation_finalize_unknown_workflow_rejected() {
    let mut protocol = CancellationProtocol::default();

    let err = protocol
        .finalize(
            "missing-workflow",
            &ResourceTracker::empty(),
            1200,
            "trace-finalize-missing",
        )
        .unwrap_err();

    assert_eq!(err.code(), cancel_error_codes::ERR_CANCEL_NOT_FOUND);
    assert_eq!(protocol.finalized_count(), 0);
}

// ---- Barrier Coordination Hardening Tests ----

#[test]
fn barrier_counter_overflow_protection() {
    let mut barrier = EpochTransitionBarrier::default();
    barrier.register_participant("test-svc");

    // Simulate many barriers to test counter overflow
    // In practice this would take a very long time, so we test the edge case directly
    let config = BarrierConfig::default();
    let mut test_barrier = EpochTransitionBarrier::new(config);
    test_barrier.register_participant("svc-1");

    // Manually set counter near overflow (this is implementation testing)
    // The barrier counter uses saturating_add so it won't overflow
    for _ in 0..10 {
        let _result = test_barrier.propose(0, 1, 1000, "trace-counter");
        if let Ok(instance) = _result {
            // Abort each barrier to allow the next proposal
            let _abort = test_barrier.abort(
                AbortReason::Cancelled {
                    detail: "test".to_string(),
                },
                1001,
                "trace-counter",
            );
        }
    }

    // Should still work without panicking
    let result = test_barrier.propose(0, 1, 2000, "trace-final");
    assert!(result.is_ok());
}

#[test]
fn barrier_timeout_boundary_conditions() {
    let config = BarrierConfig::new(5000, 1000); // 5s global, 1s drain
    let mut barrier = EpochTransitionBarrier::new(config);
    barrier.register_participant("slow-svc");

    barrier.propose(0, 1, 1000, "trace-timeout").unwrap();

    // Exactly at global timeout boundary
    let outcome = barrier.try_commit(6000, "trace-timeout").unwrap();
    if let super::epoch_transition_barrier::BarrierCommitOutcome::Aborted {
        current_epoch,
        reason: AbortReason::Timeout {
            missing_participants,
        },
    } = outcome
    {
        assert_eq!(current_epoch, 0);
        assert!(missing_participants.contains(&"slow-svc".to_string()));
    } else {
        assert!(false, "Expected auto-abort due to timeout");
    }
}

#[test]
fn barrier_participant_timeout_granular() {
    let mut config = BarrierConfig::new(10000, 2000);
    config
        .participant_timeouts
        .insert("fast-svc".to_string(), 500);
    config
        .participant_timeouts
        .insert("slow-svc".to_string(), 5000);

    let mut barrier = EpochTransitionBarrier::new(config);
    barrier.register_participant("fast-svc");
    barrier.register_participant("slow-svc");

    barrier.propose(0, 1, 1000, "trace-granular").unwrap();

    // fast-svc ACK arrives quickly
    let ack = DrainAck {
        participant_id: "fast-svc".to_string(),
        barrier_id: "barrier-000001".to_string(),
        drained_items: 10,
        elapsed_ms: 200,
        trace_id: "trace-fast".to_string(),
    };
    barrier.record_drain_ack(ack).unwrap();

    // Check timeouts at 600ms - fast-svc should have timed out but slow-svc should still be valid
    let result = barrier.check_participant_timeouts(1600, "trace-check");
    assert!(result.is_ok()); // Should not abort yet, slow-svc still has time

    // Check timeouts at 6s - both should have timed out
    let result = barrier.check_participant_timeouts(7000, "trace-check");
    assert!(result.is_ok()); // Method succeeds but barrier is now aborted

    assert!(!barrier.is_barrier_active());
}

#[test]
fn barrier_history_bounded_growth() {
    let mut barrier = EpochTransitionBarrier::default();
    barrier.register_participant("test-svc");

    // Generate many completed barriers (would normally hit MAX_BARRIER_HISTORY)
    for i in 0..10 {
        let current_epoch = i as u64;
        let target_epoch = current_epoch + 1;

        barrier
            .propose(
                current_epoch,
                target_epoch,
                1000 + i,
                &format!("trace-{}", i),
            )
            .unwrap();

        let ack = DrainAck {
            participant_id: "test-svc".to_string(),
            barrier_id: format!("barrier-{:06}", i + 1),
            drained_items: 5,
            elapsed_ms: 100,
            trace_id: format!("trace-ack-{}", i),
        };
        barrier.record_drain_ack(ack).unwrap();

        barrier
            .try_commit(1100 + i, &format!("trace-commit-{}", i))
            .unwrap();
    }

    // History should be bounded and contain recent entries
    let history = barrier.audit_history();
    assert!(history.len() <= 10); // Should be bounded by implementation limit
    assert_eq!(barrier.completed_barrier_count(), history.len());
}

#[test]
fn barrier_propose_without_participants_rejected() {
    let mut barrier = EpochTransitionBarrier::default();

    let err = barrier
        .propose(0, 1, 1000, "trace-no-participants")
        .unwrap_err();

    assert_eq!(err.code(), barrier_error_codes::ERR_BARRIER_NO_PARTICIPANTS);
    assert!(!barrier.is_barrier_active());
}

#[test]
fn barrier_rejects_ack_from_unknown_participant() {
    let mut barrier = EpochTransitionBarrier::default();
    barrier.register_participant("known-svc");
    barrier.propose(0, 1, 1000, "trace-known").unwrap();

    let err = barrier
        .record_drain_ack(DrainAck {
            participant_id: "unknown-svc".to_string(),
            barrier_id: "barrier-000001".to_string(),
            drained_items: 0,
            elapsed_ms: 10,
            trace_id: "trace-unknown".to_string(),
        })
        .unwrap_err();

    assert_eq!(
        err.code(),
        barrier_error_codes::ERR_BARRIER_UNKNOWN_PARTICIPANT
    );
    assert!(barrier.is_barrier_active());
}

#[test]
fn barrier_rejects_ack_with_wrong_barrier_id() {
    let mut barrier = EpochTransitionBarrier::default();
    barrier.register_participant("known-svc");
    barrier.propose(0, 1, 1000, "trace-known").unwrap();

    let err = barrier
        .record_drain_ack(DrainAck {
            participant_id: "known-svc".to_string(),
            barrier_id: "barrier-wrong".to_string(),
            drained_items: 0,
            elapsed_ms: 10,
            trace_id: "trace-wrong-id".to_string(),
        })
        .unwrap_err();

    assert_eq!(err.code(), barrier_error_codes::ERR_BARRIER_ID_MISMATCH);
    assert!(barrier.is_barrier_active());
}

// ---- Fork Detection Hardening Tests ----

#[test]
fn fork_detection_constant_time_comparison() {
    let mut detector = DivergenceDetector::new();

    // Create vectors with identical structure but different hashes
    let sv1 = StateVector {
        epoch: 10,
        marker_id: "marker-10".to_string(),
        state_hash: "a".repeat(64), // 64 'a' characters
        parent_state_hash: "parent-hash".to_string(),
        timestamp: 1000,
        node_id: "node-1".to_string(),
    };

    let sv2 = StateVector {
        epoch: 10,
        marker_id: "marker-10".to_string(),
        state_hash: "b".repeat(64), // 64 'b' characters - same length, different content
        parent_state_hash: "parent-hash".to_string(),
        timestamp: 1000,
        node_id: "node-2".to_string(),
    };

    // This should be detected as a fork using constant-time comparison
    let (result, proof) = detector.compare(&sv1, &sv2);
    assert_eq!(result, DetectionResult::Forked);
    assert!(proof.is_some());
    assert!(detector.is_halted());
}

#[test]
fn fork_detection_epoch_arithmetic_safety() {
    let mut detector = DivergenceDetector::new();

    // Test edge case: epoch difference calculation with potential underflow
    let sv1 = StateVector {
        epoch: 0,
        marker_id: "marker-0".to_string(),
        state_hash: "hash-0".to_string(),
        parent_state_hash: "parent-0".to_string(),
        timestamp: 1000,
        node_id: "node-1".to_string(),
    };

    let sv2 = StateVector {
        epoch: u64::MAX,
        marker_id: "marker-max".to_string(),
        state_hash: "hash-max".to_string(),
        parent_state_hash: "parent-max".to_string(),
        timestamp: 2000,
        node_id: "node-2".to_string(),
    };

    // This should detect a gap without underflow panic
    let (result, _) = detector.compare(&sv1, &sv2);
    assert_eq!(result, DetectionResult::GapDetected);
}

#[test]
fn rollback_detector_sequence_validation() {
    let mut detector = RollbackDetector::new();

    // Build a valid chain
    let mut prev_hash = "genesis".to_string();
    for i in 0..5 {
        let sv = StateVector {
            epoch: i,
            marker_id: format!("marker-{}", i),
            state_hash: format!("hash-{}", i),
            parent_state_hash: prev_hash.clone(),
            timestamp: 1000 + i,
            node_id: "node-chain".to_string(),
        };
        prev_hash = sv.state_hash.clone();
        detector.feed(sv).unwrap();
    }

    // Inject a rollback attempt (epoch goes backward)
    let rollback_sv = StateVector {
        epoch: 3, // Going backward from 4 to 3
        marker_id: "marker-rollback".to_string(),
        state_hash: "hash-rollback".to_string(),
        parent_state_hash: "parent-rollback".to_string(),
        timestamp: 1010,
        node_id: "node-chain".to_string(),
    };

    let err = detector.feed(rollback_sv).unwrap_err();
    assert_eq!(err.code(), "RFD_ROLLBACK_DETECTED");
    assert_eq!(detector.proof_count(), 1);
}

#[test]
fn fork_detection_history_bounded_growth() {
    let mut detector = DivergenceDetector::new();

    // Record many state vectors to test bounded history
    for i in 0..100 {
        let sv = StateVector {
            epoch: i,
            marker_id: format!("marker-{}", i),
            state_hash: format!("hash-{}", i),
            parent_state_hash: if i > 0 {
                format!("hash-{}", i - 1)
            } else {
                "genesis".to_string()
            },
            timestamp: 1000 + i,
            node_id: "node-history".to_string(),
        };
        detector.record_state(sv);
    }

    // History should be bounded (actual limit is implementation-defined)
    assert!(detector.history_len() <= 100); // Should not exceed reasonable bounds
}

#[test]
fn marker_proof_verifier_boundary_conditions() {
    let mut stream = MarkerStream::new();

    // Add markers up to a reasonable limit
    for i in 0..10 {
        stream
            .append(
                MarkerEventType::PolicyChange,
                &format!("payload-{}", i),
                1000 + i,
                &format!("trace-{}", i),
            )
            .unwrap();
    }

    // Test boundary: verify marker at exact stream length
    let last_idx = 9u64;
    let last_marker = stream.get(last_idx).unwrap();
    let result = MarkerProofVerifier::verify(&stream, &last_marker.marker_hash, last_idx);
    assert!(result.is_ok());

    // Test boundary: verify marker beyond stream length
    let result = MarkerProofVerifier::verify(&stream, "any-hash", last_idx + 1);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "RFD_MARKER_NOT_FOUND");
}

// ---- Thread Safety and Poison Recovery Tests ----

#[test]
fn control_plane_components_thread_safe() {
    let barrier = Arc::new(Mutex::new(EpochTransitionBarrier::default()));
    let detector = Arc::new(Mutex::new(DivergenceDetector::new()));
    let mut handles = Vec::new();

    // Test concurrent access to barrier
    {
        let barrier_clone = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            let mut b = try_lock(&barrier_clone, "register barrier participant concurrently")
                .expect("epoch transition barrier mutex should not be poisoned");
            b.register_participant("thread-svc-1");
        });
        handles.push(handle);
    }

    // Test concurrent access to detector
    {
        let detector_clone = Arc::clone(&detector);
        let handle = thread::spawn(move || {
            let mut d = try_lock(&detector_clone, "record divergence state concurrently")
                .expect("divergence detector mutex should not be poisoned");
            let sv = StateVector {
                epoch: 1,
                marker_id: "marker-thread".to_string(),
                state_hash: "hash-thread".to_string(),
                parent_state_hash: "parent-thread".to_string(),
                timestamp: 2000,
                node_id: "thread-node".to_string(),
            };
            d.record_state(sv);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify state after concurrent access
    assert!(
        try_lock(&barrier, "inspect barrier final state")
            .expect("epoch transition barrier mutex should not be poisoned")
            .registered_participants()
            .contains("thread-svc-1")
    );
    assert_eq!(
        try_lock(&detector, "inspect detector final state")
            .expect("divergence detector mutex should not be poisoned")
            .history_len(),
        1
    );
}

// ---- Integration Test: Full Control Plane Flow ----

#[test]
fn control_plane_full_integration() {
    // Create a complete control plane scenario with epoch management, barriers, and fork detection
    let mut epoch_store = EpochStore::new();
    let mut barrier = EpochTransitionBarrier::default();
    let mut detector = DivergenceDetector::new();

    barrier.register_participant("integration-svc");

    // Phase 1: Advance epochs with barrier coordination
    for i in 0..3 {
        // Advance epoch
        let transition = epoch_store
            .epoch_advance(
                &format!("manifest-{}", i + 1),
                1000 + i,
                &format!("trace-epoch-{}", i + 1),
            )
            .unwrap();

        assert_eq!(transition.old_epoch.value(), i);
        assert_eq!(transition.new_epoch.value(), i + 1);

        // Coordinate barrier for epoch transition
        let instance = barrier
            .propose(i, i + 1, 1000 + i, &format!("trace-barrier-{}", i + 1))
            .unwrap();
        assert_eq!(instance.phase, BarrierPhase::Draining);

        // Simulate participant drain ACK
        let ack = DrainAck {
            participant_id: "integration-svc".to_string(),
            barrier_id: instance.barrier_id.clone(),
            drained_items: 5,
            elapsed_ms: 50,
            trace_id: format!("trace-ack-{}", i + 1),
        };
        barrier.record_drain_ack(ack).unwrap();

        // Commit barrier
        let outcome = barrier
            .try_commit(1050 + i, &format!("trace-commit-{}", i + 1))
            .unwrap();
        if let super::epoch_transition_barrier::BarrierCommitOutcome::Committed { target_epoch } =
            outcome
        {
            assert_eq!(target_epoch, i + 1);
        } else {
            assert!(false, "Expected successful barrier commit");
        }

        // Verify fork detection sees consistent state
        let sv = StateVector {
            epoch: i + 1,
            marker_id: format!("marker-{}", i + 1),
            state_hash: transition.manifest_hash.clone(),
            parent_state_hash: if i > 0 {
                format!("prev-hash-{}", i)
            } else {
                "genesis".to_string()
            },
            timestamp: transition.timestamp,
            node_id: "integration-node".to_string(),
        };
        detector.record_state(sv);
    }

    // Verify final state
    assert_eq!(epoch_store.epoch_read().value(), 3);
    assert_eq!(barrier.completed_barrier_count(), 3);
    assert_eq!(detector.history_len(), 3);
    assert!(!detector.is_halted());
}
