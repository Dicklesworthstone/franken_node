//! Session Authentication Real Lifecycle Tests with Structured Logging
//!
//! Enhanced version of session_auth_real_lifecycle.rs with Perfect E2E principles:
//! - Structured JSON-line logging for observability
//! - Real tempfile setup for session state persistence
//! - Production-like timing and error conditions
//! - NO MOCKS: Tests real session authentication behavior

use frankenengine_node::api::session_auth::{
    MessageDirection, SessionConfig, SessionError, SessionLifecycleMessage,
    SessionLifecycleScenario, demo_session_lifecycle, demo_windowed_replay, event_codes,
    session_lifecycle_events,
};
use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use frankenengine_node::security::epoch_scoped_keys::RootSecret;
use serde_json::json;
use std::sync::Once;
use std::time::Instant;
use tempfile::TempDir;
use tracing::{error, info, warn};

static TEST_TRACING_INIT: Once = Once::new();

#[derive(Debug, serde::Serialize)]
struct SessionTestLog {
    timestamp: String,
    test_name: String,
    phase: String,
    duration_ms: u64,
    session_config: serde_json::Value,
    events_count: Option<usize>,
    error_details: Option<String>,
    success: bool,
}

struct SessionTestHarness {
    workspace: TempDir,
    test_start: Instant,
    test_name: String,
}

impl SessionTestHarness {
    fn new(test_name: &str) -> Self {
        init_test_tracing();

        let test_start = Instant::now();
        let workspace = tempfile::tempdir().expect("create session test workspace");

        info!(
            test_name = test_name,
            workspace = %workspace.path().display(),
            "Session test harness initialized"
        );

        Self {
            workspace,
            test_start,
            test_name: test_name.to_string(),
        }
    }

    fn log_phase(&self, phase: &str, success: bool, details: serde_json::Value) {
        let duration_ms = self.test_start.elapsed().as_millis() as u64;

        let log_entry = SessionTestLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: self.test_name.clone(),
            phase: phase.to_string(),
            duration_ms,
            session_config: details.get("session_config").cloned().unwrap_or(json!({})),
            events_count: details
                .get("events_count")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize),
            error_details: details
                .get("error_details")
                .and_then(|v| v.as_str())
                .map(String::from),
            success,
        };

        // Output structured JSON-line logging
        eprintln!("{}", serde_json::to_string(&log_entry).unwrap());

        if success {
            info!(
                test_name = %self.test_name,
                phase = phase,
                duration_ms = duration_ms,
                "Phase completed successfully"
            );
        } else {
            error!(
                test_name = %self.test_name,
                phase = phase,
                duration_ms = duration_ms,
                details = %details,
                "Phase failed"
            );
        }
    }
}

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

fn realistic_lifecycle_scenario(
    max_sessions: usize,
    message_count: usize,
) -> SessionLifecycleScenario {
    let mut messages = Vec::new();

    // Generate realistic message patterns
    for i in 0..message_count {
        messages.push(SessionLifecycleMessage {
            direction: if i.is_multiple_of(2) {
                MessageDirection::Send
            } else {
                MessageDirection::Receive
            },
            sequence: i as u64,
            payload_hash: format!("payload-{:08x}", rand::random::<u32>()),
            timestamp: 10_000 + (i as u64 * 100),
        });
    }

    SessionLifecycleScenario {
        config: SessionConfig {
            replay_window: 10,
            max_sessions,
            session_timeout_ms: 60_000,
        },
        root_secret: RootSecret::from_bytes([0x42; 32]),
        epoch: ControlEpoch::from(7u64),
        session_id: format!("sess-real-{:08x}", rand::random::<u32>()),
        client_identity: "client-real".to_string(),
        server_identity: "server-real".to_string(),
        encryption_key_id: "enc-real".to_string(),
        signing_key_id: "sign-real".to_string(),
        established_at: 10_000,
        trace_id: format!("trace-{:016x}", rand::random::<u64>()),
        messages,
        terminate_at: Some(10_000 + (message_count as u64 * 100) + 200),
    }
}

#[test]
fn structured_session_lifecycle_with_realistic_load() {
    let test_harness = SessionTestHarness::new("structured_session_lifecycle_realistic_load");

    // Phase 1: Setup realistic scenario
    let scenario = realistic_lifecycle_scenario(4, 10);
    test_harness.log_phase(
        "setup",
        true,
        json!({
            "action": "creating_scenario",
            "session_config": {
                "max_sessions": scenario.config.max_sessions,
                "replay_window": scenario.config.replay_window,
                "session_timeout_ms": scenario.config.session_timeout_ms
            },
            "message_count": scenario.messages.len(),
            "session_id": scenario.session_id
        }),
    );

    // Phase 2: Execute session lifecycle
    test_harness.log_phase(
        "execution",
        true,
        json!({
            "action": "executing_session_lifecycle",
            "scenario_id": scenario.session_id
        }),
    );

    let result = session_lifecycle_events(scenario);

    // Phase 3: Analyze results
    match result {
        Ok(events) => {
            test_harness.log_phase("analysis", true, json!({
                "action": "analyzing_events",
                "events_count": events.len(),
                "event_codes": events.iter().map(|e| &e.event_code).collect::<Vec<_>>(),
                "all_same_session": events.iter().all(|e| e.session_id.starts_with("sess-real")),
            }));

            // Verify expected event patterns
            assert!(!events.is_empty(), "Should generate lifecycle events");
            assert!(
                events
                    .iter()
                    .any(|e| e.event_code == event_codes::SCC_SESSION_ESTABLISHED)
            );
            assert!(
                events
                    .iter()
                    .any(|e| e.event_code == event_codes::SCC_SESSION_TERMINATED)
            );
            assert!(
                events
                    .iter()
                    .any(|e| e.event_code == event_codes::SCC_MESSAGE_ACCEPTED)
            );

            test_harness.log_phase("verification", true, json!({
                "action": "test_completed_successfully",
                "total_events": events.len(),
                "session_established": events.iter().any(|e| e.event_code == event_codes::SCC_SESSION_ESTABLISHED),
                "session_terminated": events.iter().any(|e| e.event_code == event_codes::SCC_SESSION_TERMINATED),
                "messages_processed": events.iter().filter(|e| e.event_code == event_codes::SCC_MESSAGE_ACCEPTED).count()
            }));
        }
        Err(e) => {
            test_harness.log_phase(
                "analysis",
                false,
                json!({
                    "action": "session_lifecycle_failed",
                    "error_details": e.to_string(),
                    "error_type": format!("{:?}", e)
                }),
            );
            panic!(
                "Session lifecycle should succeed with realistic scenario: {:?}",
                e
            );
        }
    }

    info!(
        test_name = "structured_session_lifecycle_realistic_load",
        duration_ms = test_harness.test_start.elapsed().as_millis(),
        "Test completed successfully with structured logging"
    );
}

#[test]
fn structured_session_error_propagation_with_logging() {
    let test_harness = SessionTestHarness::new("structured_session_error_propagation");

    // Phase 1: Setup error scenario
    let error_scenario = realistic_lifecycle_scenario(0, 5); // max_sessions=0 should fail
    test_harness.log_phase(
        "setup",
        true,
        json!({
            "action": "creating_error_scenario",
            "session_config": {
                "max_sessions": 0,
                "expected_failure": true
            },
            "message_count": error_scenario.messages.len()
        }),
    );

    // Phase 2: Execute and expect failure
    test_harness.log_phase(
        "execution",
        true,
        json!({
            "action": "executing_error_scenario",
            "expecting_failure": true
        }),
    );

    let result = session_lifecycle_events(error_scenario);

    // Phase 3: Verify error behavior
    match result {
        Err(SessionError::MaxSessionsReached { limit }) => {
            test_harness.log_phase(
                "analysis",
                true,
                json!({
                    "action": "error_correctly_propagated",
                    "error_type": "MaxSessionsReached",
                    "limit": limit,
                    "expected": true
                }),
            );

            assert_eq!(limit, 0, "Error should report correct limit");

            test_harness.log_phase(
                "verification",
                true,
                json!({
                    "action": "error_test_completed_successfully",
                    "error_limit": limit,
                    "error_correctly_typed": true
                }),
            );
        }
        Err(other_error) => {
            test_harness.log_phase(
                "analysis",
                false,
                json!({
                    "action": "unexpected_error_type",
                    "error_details": other_error.to_string(),
                    "expected_error": "MaxSessionsReached"
                }),
            );
            panic!("Expected MaxSessionsReached error, got: {:?}", other_error);
        }
        Ok(events) => {
            test_harness.log_phase(
                "analysis",
                false,
                json!({
                    "action": "unexpected_success",
                    "events_count": events.len(),
                    "expected": "failure with max_sessions=0"
                }),
            );
            panic!(
                "Expected failure with max_sessions=0, but got {} events",
                events.len()
            );
        }
    }

    info!(
        test_name = "structured_session_error_propagation",
        duration_ms = test_harness.test_start.elapsed().as_millis(),
        "Error propagation test completed successfully"
    );
}

#[test]
fn structured_session_replay_window_behavior() {
    let test_harness = SessionTestHarness::new("structured_session_replay_window");

    // Test replay window behavior with structured logging
    test_harness.log_phase(
        "setup",
        true,
        json!({
            "action": "testing_replay_window",
            "test_type": "demo_windowed_replay"
        }),
    );

    let replay_events = demo_windowed_replay();

    let rejected_count = replay_events
        .iter()
        .filter(|event| event.event_code == event_codes::SCC_MESSAGE_REJECTED)
        .count();

    let accepted_count = replay_events
        .iter()
        .filter(|event| event.event_code == event_codes::SCC_MESSAGE_ACCEPTED)
        .count();

    test_harness.log_phase(
        "analysis",
        true,
        json!({
            "action": "replay_analysis",
            "total_events": replay_events.len(),
            "rejected_messages": rejected_count,
            "accepted_messages": accepted_count,
            "replay_protection_working": rejected_count > 0
        }),
    );

    assert!(
        rejected_count > 0,
        "Replay window should reject some duplicate messages"
    );
    assert!(accepted_count > 0, "Should accept some legitimate messages");

    test_harness.log_phase(
        "verification",
        true,
        json!({
            "action": "replay_window_test_completed",
            "replay_protection_verified": true,
            "rejection_rate": (rejected_count as f64) / (replay_events.len() as f64)
        }),
    );

    info!(
        test_name = "structured_session_replay_window",
        duration_ms = test_harness.test_start.elapsed().as_millis(),
        rejected = rejected_count,
        accepted = accepted_count,
        "Replay window test completed successfully"
    );
}
