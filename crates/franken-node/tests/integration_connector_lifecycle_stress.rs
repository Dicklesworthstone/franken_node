//! Real-service integration tests for connector lifecycle under stress.
//!
//! NO MOCKS: Tests actual connector state machine with real concurrency,
//! resource contention, and failure recovery. Validates race conditions
//! that only appear under realistic load.
//!
//! Mock Risk Score: 20 (Resource leak × Concurrency bugs)
//! Why no mocks: State transitions, resource cleanup, and race conditions
//! can only be validated under real concurrent stress.

use frankenengine_node::connector::{
    cancellation_protocol::{CancellationPhase, CancellationProtocol, WorkflowKind},
    lease_service::{LeasePurpose, LeaseService},
    lifecycle::{ConnectorState, transition},
};
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, Semaphore};

/// Test harness for real connector lifecycle stress testing
#[derive(Clone)]
struct ConnectorLifecycleStressHarness {
    connector_states: Arc<RwLock<HashMap<String, ConnectorState>>>,
    lease_service: Arc<Mutex<LeaseService>>,
    test_start: Instant,
    transition_logs: Arc<Mutex<Vec<StateTransitionLog>>>,
    resource_tracker: Arc<Mutex<ResourceTracker>>,
}

#[derive(Debug, Clone)]
struct StateTransitionLog {
    connector_id: String,
    from_state: ConnectorState,
    to_state: ConnectorState,
    timestamp_ms: u64,
    duration_ms: u64,
    concurrent_transitions: usize,
    success: bool,
    error: Option<String>,
}

#[derive(Debug, Default)]
struct ResourceTracker {
    active_connectors: BTreeSet<String>,
    leaked_resources: HashMap<String, String>,
    peak_concurrent_operations: usize,
    total_state_transitions: usize,
}

impl ConnectorLifecycleStressHarness {
    async fn new() -> Self {
        Self {
            connector_states: Arc::new(RwLock::new(HashMap::new())),
            lease_service: Arc::new(Mutex::new(LeaseService::new())),
            test_start: Instant::now(),
            transition_logs: Arc::new(Mutex::new(Vec::new())),
            resource_tracker: Arc::new(Mutex::new(ResourceTracker::default())),
        }
    }

    /// Test state transition under real concurrency pressure
    async fn stress_transition_with_tracking(
        &self,
        connector_id: &str,
        target_state: ConnectorState,
    ) -> Result<Duration, String> {
        let start = Instant::now();

        let current_concurrent = {
            let mut tracker = self.resource_tracker.lock().await;
            tracker.active_connectors.insert(connector_id.to_string());
            tracker.total_state_transitions += 1;
            let active = tracker.active_connectors.len();
            tracker.peak_concurrent_operations = tracker.peak_concurrent_operations.max(active);
            active
        };

        // Hold the state lock + log append atomically per transition so causal
        // ordering is recorded faithfully under multi-task contention.
        let (current_state, transition_result, timestamp) = {
            let mut states = self.connector_states.write().await;
            let current_state = states
                .get(connector_id)
                .copied()
                .unwrap_or(ConnectorState::Discovered);
            let transition_result = transition(current_state, target_state);
            if let Ok(next_state) = transition_result {
                states.insert(connector_id.to_string(), next_state);
            }
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix epoch")
                .as_millis() as u64;
            let duration = start.elapsed();
            let log = StateTransitionLog {
                connector_id: connector_id.to_string(),
                from_state: current_state,
                to_state: target_state,
                timestamp_ms: timestamp,
                duration_ms: duration.as_millis() as u64,
                concurrent_transitions: current_concurrent,
                success: transition_result.is_ok(),
                error: transition_result.as_ref().err().map(ToString::to_string),
            };
            self.transition_logs.lock().await.push(log);
            (current_state, transition_result, timestamp)
        };

        if matches!(
            transition_result,
            Ok(ConnectorState::Stopped | ConnectorState::Failed)
        ) {
            let mut tracker = self.resource_tracker.lock().await;
            tracker.active_connectors.remove(connector_id);
        }

        let duration = start.elapsed();
        let error_text = transition_result.as_ref().err().map(ToString::to_string);
        eprintln!(
            "{}",
            json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "suite": "connector_lifecycle_stress",
                "phase": "state_transition",
                "connector_id": connector_id,
                "from_state": format!("{current_state:?}"),
                "to_state": format!("{target_state:?}"),
                "timestamp_ms": timestamp,
                "duration_ms": duration.as_millis() as u64,
                "concurrent_transitions": current_concurrent,
                "success": transition_result.is_ok(),
                "error": error_text,
                "event": "lifecycle_transition"
            })
        );

        match transition_result {
            Ok(_) => Ok(duration),
            Err(err) => Err(err.to_string()),
        }
    }

    /// Massive concurrent stress test with real resource contention
    async fn massive_concurrent_lifecycle_stress(
        &self,
        connector_count: usize,
        transition_rounds: usize,
    ) -> Vec<Result<Duration, String>> {
        let semaphore = Arc::new(Semaphore::new(30));
        let mut handles = Vec::new();

        for connector_idx in 0..connector_count {
            let connector_id = format!("stress-connector-{connector_idx:04}");
            let harness = self.clone();
            let sem = semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore permit");
                let start = Instant::now();

                let initial_sequence = [
                    ConnectorState::Verified,
                    ConnectorState::Installed,
                    ConnectorState::Configured,
                    ConnectorState::Active,
                    ConnectorState::Paused,
                    ConnectorState::Active,
                    ConnectorState::Cancelling,
                    ConnectorState::Stopped,
                ];
                let restart_sequence = [
                    ConnectorState::Configured,
                    ConnectorState::Active,
                    ConnectorState::Paused,
                    ConnectorState::Active,
                    ConnectorState::Cancelling,
                    ConnectorState::Stopped,
                ];

                for round in 0..transition_rounds {
                    let seq: &[ConnectorState] = if round == 0 {
                        &initial_sequence
                    } else {
                        &restart_sequence
                    };
                    let mut active_lease_id: Option<String> = None;

                    for &target_state in seq {
                        harness
                            .stress_transition_with_tracking(&connector_id, target_state)
                            .await?;

                        if target_state == ConnectorState::Active && active_lease_id.is_none() {
                            let mut leases = harness.lease_service.lock().await;
                            let now_secs = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .expect("unix epoch")
                                .as_secs();
                            let trace_id = format!("trace-stress-{connector_idx}-{round}");
                            let ts = chrono::Utc::now().to_rfc3339();
                            let lease = leases
                                .grant(
                                    &format!("owner-{connector_idx}-{round}"),
                                    LeasePurpose::Operation,
                                    60,
                                    now_secs,
                                    &trace_id,
                                    &ts,
                                )
                                .map_err(|err| err.to_string())?;
                            active_lease_id = Some(lease.lease_id);
                        }

                        if target_state == ConnectorState::Stopped
                            && let Some(lease_id) = active_lease_id.take()
                        {
                            let mut leases = harness.lease_service.lock().await;
                            let trace_id = format!("trace-revoke-{connector_idx}-{round}");
                            let ts = chrono::Utc::now().to_rfc3339();
                            let _ = leases.revoke(&lease_id, &trace_id, &ts);
                        }

                        tokio::time::sleep(Duration::from_micros(50)).await;
                    }
                }

                {
                    let mut tracker = harness.resource_tracker.lock().await;
                    tracker.active_connectors.remove(&connector_id);
                }

                Ok(start.elapsed())
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(err) => results.push(Err(format!("Concurrent task panicked: {err}"))),
            }
        }

        results
    }

    /// Test three-phase cancellation protocol (REQUEST -> DRAIN -> FINALIZE) under stress
    async fn stress_cancellation_protocol(
        &self,
        connector_count: usize,
    ) -> Vec<(String, Duration, bool)> {
        let mut cancellation_results = Vec::new();

        for i in 0..connector_count {
            let connector_id = format!("cancel-stress-{i:04}");

            for state in [
                ConnectorState::Verified,
                ConnectorState::Installed,
                ConnectorState::Configured,
                ConnectorState::Active,
            ] {
                let _ = self
                    .stress_transition_with_tracking(&connector_id, state)
                    .await;
            }

            let cancel_start = Instant::now();
            let trace_id = format!("trace-cancel-{i:04}");
            let mut protocol =
                CancellationProtocol::for_workflow(&WorkflowKind::Lifecycle, &trace_id);
            protocol.resource_guard_mut().acquire("socket");
            protocol.resource_guard_mut().acquire("session_handle");
            protocol.register_child();

            // Phase 1: Enter Cancelling state + protocol REQUEST
            let enter_result = self
                .stress_transition_with_tracking(&connector_id, ConnectorState::Cancelling)
                .await;
            if enter_result.is_err() || protocol.request().is_err() {
                cancellation_results.push((connector_id, cancel_start.elapsed(), false));
                continue;
            }
            assert_eq!(protocol.phase(), CancellationPhase::Requested);

            // Phase 2: Complete child + release resources + DRAIN within timeout
            let drain_outcome = tokio::time::timeout(Duration::from_millis(500), async {
                tokio::time::sleep(Duration::from_micros(100)).await;
                protocol.complete_child();
                assert!(protocol.resource_guard_mut().release("socket"));
                assert!(protocol.resource_guard_mut().release("session_handle"));
                let elapsed_ms = cancel_start.elapsed().as_millis() as u64;
                protocol.drain(elapsed_ms)?;
                protocol.finalize()
            })
            .await;

            let protocol_ok = matches!(drain_outcome, Ok(Ok(_)))
                && protocol.is_completed()
                && !protocol.resource_guard().has_leaks();
            if !protocol_ok {
                let mut tracker = self.resource_tracker.lock().await;
                tracker
                    .leaked_resources
                    .insert(connector_id.clone(), "cancellation_incomplete".to_string());
                cancellation_results.push((connector_id, cancel_start.elapsed(), false));
                continue;
            }

            // Phase 3: Final transition to Stopped
            let stop_result = self
                .stress_transition_with_tracking(&connector_id, ConnectorState::Stopped)
                .await;
            let total_duration = cancel_start.elapsed();
            let success = stop_result.is_ok();

            eprintln!(
                "{}",
                json!({
                    "ts": chrono::Utc::now().to_rfc3339(),
                    "suite": "connector_lifecycle_stress",
                    "phase": "cancellation_protocol",
                    "connector_id": connector_id,
                    "cancellation_duration_ms": total_duration.as_millis(),
                    "success": success,
                    "event": "cancellation_complete"
                })
            );

            cancellation_results.push((connector_id, total_duration, success));
        }

        cancellation_results
    }

    /// Resource leak detection (real resource tracking, no mocks)
    async fn detect_resource_leaks(&self) -> (usize, Vec<String>) {
        let tracker = self.resource_tracker.lock().await;
        let mut leaked_connectors: Vec<String> =
            tracker.active_connectors.iter().cloned().collect();
        for key in tracker.leaked_resources.keys() {
            if !leaked_connectors.contains(key) {
                leaked_connectors.push(key.clone());
            }
        }
        let leaked_count = leaked_connectors.len();

        eprintln!(
            "{}",
            json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "suite": "connector_lifecycle_stress",
                "phase": "resource_leak_detection",
                "active_connectors": leaked_count,
                "leaked_connectors": leaked_connectors,
                "peak_concurrent_operations": tracker.peak_concurrent_operations,
                "total_transitions": tracker.total_state_transitions,
                "event": "resource_audit"
            })
        );

        (leaked_count, leaked_connectors)
    }

    /// Race condition detection through causal state-log continuity analysis
    async fn analyze_race_conditions(&self) -> RaceConditionAnalysis {
        let logs = self.transition_logs.lock().await;
        let mut analysis = RaceConditionAnalysis::default();
        let mut last_committed_by_connector: HashMap<&str, &StateTransitionLog> = HashMap::new();

        for log in logs.iter() {
            if let Some(prev) = last_committed_by_connector.get(log.connector_id.as_str()) {
                let time_gap = log.timestamp_ms.saturating_sub(prev.timestamp_ms);
                // Genuine state-machine race: a transition observed a different
                // `from_state` than the last committed `to_state` for this connector.
                if log.from_state != prev.to_state {
                    analysis.potential_races += 1;
                }
                if time_gap < 100 && !log.success {
                    analysis.state_conflicts += 1;
                }
            }
            if log.success {
                last_committed_by_connector.insert(log.connector_id.as_str(), log);
            }
        }

        analysis.total_transitions = logs.len();
        analysis.concurrent_transitions = logs
            .iter()
            .filter(|log| log.concurrent_transitions > 1)
            .count();

        eprintln!(
            "{}",
            json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "suite": "connector_lifecycle_stress",
                "phase": "race_condition_analysis",
                "total_transitions": analysis.total_transitions,
                "concurrent_transitions": analysis.concurrent_transitions,
                "potential_races": analysis.potential_races,
                "state_conflicts": analysis.state_conflicts,
                "event": "race_analysis"
            })
        );

        analysis
    }

    fn export_stress_summary(&self) -> serde_json::Value {
        let total_duration = self.test_start.elapsed();

        json!({
            "suite": "connector_lifecycle_stress",
            "total_stress_duration_ms": total_duration.as_millis(),
            "stress_completed_at": chrono::Utc::now().to_rfc3339(),
        })
    }
}

#[derive(Debug, Default)]
struct RaceConditionAnalysis {
    total_transitions: usize,
    concurrent_transitions: usize,
    potential_races: usize,
    state_conflicts: usize,
}

#[tokio::test]
async fn test_connector_lifecycle_massive_concurrent_stress() {
    let harness = ConnectorLifecycleStressHarness::new().await;

    const STRESS_CONNECTOR_COUNT: usize = 50;
    const TRANSITION_ROUNDS: usize = 3;

    let stress_results = harness
        .massive_concurrent_lifecycle_stress(STRESS_CONNECTOR_COUNT, TRANSITION_ROUNDS)
        .await;

    let successful = stress_results.iter().filter(|r| r.is_ok()).count();
    let failed = stress_results.iter().filter(|r| r.is_err()).count();

    eprintln!(
        "{}",
        json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "suite": "connector_lifecycle_stress",
            "test": "massive_concurrent_stress",
            "connector_count": STRESS_CONNECTOR_COUNT,
            "transition_rounds": TRANSITION_ROUNDS,
            "successful_connectors": successful,
            "failed_connectors": failed,
            "success_rate": successful as f64 / stress_results.len() as f64,
            "event": "massive_stress_complete"
        })
    );

    let success_rate = successful as f64 / stress_results.len() as f64;
    assert!(
        success_rate >= 0.7,
        "Success rate under massive stress should be >= 70%, got {:.1}%",
        success_rate * 100.0
    );

    eprintln!("{}", harness.export_stress_summary());
}

#[tokio::test]
async fn test_cancellation_protocol_stress() {
    let harness = ConnectorLifecycleStressHarness::new().await;

    const CANCELLATION_STRESS_COUNT: usize = 20;

    let cancellation_results = harness
        .stress_cancellation_protocol(CANCELLATION_STRESS_COUNT)
        .await;

    let successful_cancellations = cancellation_results
        .iter()
        .filter(|(_, _, success)| *success)
        .count();
    let avg_cancellation_time: f64 = cancellation_results
        .iter()
        .map(|(_, duration, _)| duration.as_millis() as f64)
        .sum::<f64>()
        / cancellation_results.len() as f64;

    eprintln!(
        "{}",
        json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "suite": "connector_lifecycle_stress",
            "test": "cancellation_protocol_stress",
            "total_cancellations": CANCELLATION_STRESS_COUNT,
            "successful_cancellations": successful_cancellations,
            "avg_cancellation_time_ms": avg_cancellation_time,
            "success_rate": successful_cancellations as f64 / CANCELLATION_STRESS_COUNT as f64,
            "event": "cancellation_stress_complete"
        })
    );

    let success_rate = successful_cancellations as f64 / CANCELLATION_STRESS_COUNT as f64;
    assert!(
        success_rate >= 0.85,
        "Cancellation success rate should be >= 85%, got {:.1}%",
        success_rate * 100.0
    );

    eprintln!("{}", harness.export_stress_summary());
}

#[tokio::test]
async fn test_resource_leak_detection_under_stress() {
    let harness = ConnectorLifecycleStressHarness::new().await;

    for i in 0..10 {
        let connector_id = format!("leak-test-{i}");
        for state in [
            ConnectorState::Verified,
            ConnectorState::Installed,
            ConnectorState::Configured,
            ConnectorState::Active,
            ConnectorState::Cancelling,
            ConnectorState::Stopped,
        ] {
            harness
                .stress_transition_with_tracking(&connector_id, state)
                .await
                .expect("legal lifecycle progression");
        }
    }

    let (leaked_count, leaked_connectors) = harness.detect_resource_leaks().await;

    eprintln!(
        "{}",
        json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "suite": "connector_lifecycle_stress",
            "test": "resource_leak_detection",
            "leaked_resources": leaked_count,
            "leaked_connectors": leaked_connectors,
            "event": "leak_detection_complete"
        })
    );

    assert!(
        leaked_count <= 2,
        "Should have minimal resource leaks, found: {leaked_count}"
    );

    eprintln!("{}", harness.export_stress_summary());
}

#[tokio::test]
async fn test_race_condition_detection() {
    let harness = ConnectorLifecycleStressHarness::new().await;

    let mut handles = Vec::new();
    for i in 0..5 {
        let connector_id = format!("race-test-{i}");
        let harness_clone = harness.clone();

        let handle = tokio::spawn(async move {
            for round in 0..3 {
                let seq: &[ConnectorState] = if round == 0 {
                    &[
                        ConnectorState::Verified,
                        ConnectorState::Installed,
                        ConnectorState::Configured,
                        ConnectorState::Active,
                        ConnectorState::Stopped,
                    ]
                } else {
                    &[
                        ConnectorState::Configured,
                        ConnectorState::Active,
                        ConnectorState::Stopped,
                    ]
                };
                for &state in seq {
                    let _ = harness_clone
                        .stress_transition_with_tracking(&connector_id, state)
                        .await;
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("concurrent stress task");
    }

    let race_analysis = harness.analyze_race_conditions().await;

    eprintln!(
        "{}",
        json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "suite": "connector_lifecycle_stress",
            "test": "race_condition_detection",
            "total_transitions": race_analysis.total_transitions,
            "concurrent_transitions": race_analysis.concurrent_transitions,
            "potential_races": race_analysis.potential_races,
            "state_conflicts": race_analysis.state_conflicts,
            "event": "race_detection_complete"
        })
    );

    assert!(
        race_analysis.potential_races <= 2,
        "Should have minimal race conditions, found: {}",
        race_analysis.potential_races
    );

    eprintln!("{}", harness.export_stress_summary());
}
