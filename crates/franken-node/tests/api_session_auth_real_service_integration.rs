//! Real-service integration tests for session-authenticated API endpoints.
//!
//! Tests API endpoints with real session authentication under load,
//! validates session lifecycle, concurrent authentication, and error paths.
//! No mocked authentication - tests against real session store and auth logic.
//!
//! Follows anti-mock principles:
//! - Real session authentication service
//! - Load testing with concurrent sessions
//! - Structured logging with auth timing
//! - Comprehensive error path coverage

use frankenengine_node::api::{
    error::ApiError,
    middleware::AuthMiddleware,
    service::ApiService,
    session_auth::{
        SessionAuthenticatedControlChannel, SessionManager, SessionState, error_codes, event_codes,
    },
};
use frankenengine_node::connector::control_channel::Direction;
use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use frankenengine_node::security::{
    constant_time,
    epoch_scoped_keys::{RootSecret, derive_epoch_key},
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};

type HmacSha256 = Hmac<Sha256>;

/// Real-service API authentication test harness
#[derive(Debug)]
struct ApiSessionAuthTestHarness {
    session_manager: Arc<RwLock<SessionManager>>,
    auth_middleware: Arc<AuthMiddleware>,
    api_service: Arc<ApiService>,
    root_secret: RootSecret,
    test_start: Instant,
    auth_logs: Vec<AuthOperationLog>,
}

#[derive(Debug, Clone)]
struct AuthOperationLog {
    operation: String,
    timestamp: Instant,
    session_id: String,
    client_id: String,
    duration_ms: u64,
    success: bool,
    auth_method: String,
    error_code: Option<String>,
    concurrent_sessions: usize,
}

impl ApiSessionAuthTestHarness {
    async fn new() -> Self {
        let root_secret = RootSecret::generate_test_key();
        let session_manager = Arc::new(RwLock::new(SessionManager::new(root_secret.clone())));
        let auth_middleware = Arc::new(AuthMiddleware::new(session_manager.clone()));
        let api_service = Arc::new(ApiService::new(auth_middleware.clone()));

        Self {
            session_manager,
            auth_middleware,
            api_service,
            root_secret,
            test_start: Instant::now(),
            auth_logs: Vec::new(),
        }
    }

    async fn establish_authenticated_session(
        &mut self,
        client_id: &str,
    ) -> Result<(String, Duration), String> {
        let start = Instant::now();
        let mut session_manager = self.session_manager.write().await;

        // Simulate handshake transcript binding
        let handshake_data = format!(
            "handshake-{}-{}",
            client_id,
            chrono::Utc::now().timestamp_millis()
        );
        let transcript_hash = self.compute_transcript_hash(&handshake_data);

        // Establish session with real HMAC verification
        let session_result = session_manager
            .establish_session(client_id, &transcript_hash, Duration::from_secs(3600))
            .await;

        let duration = start.elapsed();
        let concurrent_sessions = session_manager.active_session_count().await;

        match session_result {
            Ok(session_id) => {
                let log = AuthOperationLog {
                    operation: "establish_session".to_string(),
                    timestamp: start,
                    session_id: session_id.clone(),
                    client_id: client_id.to_string(),
                    duration_ms: duration.as_millis() as u64,
                    success: true,
                    auth_method: "transcript_hmac".to_string(),
                    error_code: None,
                    concurrent_sessions,
                };

                eprintln!(
                    "{}",
                    json!({
                        "ts": chrono::Utc::now().to_rfc3339(),
                        "suite": "api_session_auth_integration",
                        "operation": "establish_session",
                        "session_id": session_id,
                        "client_id": client_id,
                        "duration_ms": log.duration_ms,
                        "concurrent_sessions": concurrent_sessions,
                        "auth_method": "transcript_hmac",
                        "event": "session_established"
                    })
                );

                self.auth_logs.push(log);
                Ok((session_id, duration))
            }
            Err(e) => {
                let error_code = format!("{:?}", e);
                let log = AuthOperationLog {
                    operation: "establish_session".to_string(),
                    timestamp: start,
                    session_id: "".to_string(),
                    client_id: client_id.to_string(),
                    duration_ms: duration.as_millis() as u64,
                    success: false,
                    auth_method: "transcript_hmac".to_string(),
                    error_code: Some(error_code.clone()),
                    concurrent_sessions,
                };

                eprintln!(
                    "{}",
                    json!({
                        "ts": chrono::Utc::now().to_rfc3339(),
                        "suite": "api_session_auth_integration",
                        "operation": "establish_session_failed",
                        "client_id": client_id,
                        "duration_ms": log.duration_ms,
                        "error_code": error_code,
                        "event": "session_establishment_failed"
                    })
                );

                self.auth_logs.push(log);
                Err(error_code)
            }
        }
    }

    async fn authenticated_api_request(
        &mut self,
        session_id: &str,
        endpoint: &str,
        payload: &str,
    ) -> Result<(String, Duration), String> {
        let start = Instant::now();

        // Prepare authenticated request with real session verification
        let auth_result = self
            .auth_middleware
            .authenticate_request(session_id, endpoint, payload.as_bytes())
            .await;

        match auth_result {
            Ok(auth_context) => {
                // Proceed with actual API request processing
                let api_result = self
                    .api_service
                    .process_authenticated_request(&auth_context, endpoint, payload)
                    .await;

                let duration = start.elapsed();

                match api_result {
                    Ok(response) => {
                        eprintln!(
                            "{}",
                            json!({
                                "ts": chrono::Utc::now().to_rfc3339(),
                                "suite": "api_session_auth_integration",
                                "operation": "authenticated_request",
                                "session_id": session_id,
                                "endpoint": endpoint,
                                "duration_ms": duration.as_millis(),
                                "response_size": response.len(),
                                "success": true,
                                "event": "api_request_success"
                            })
                        );

                        Ok((response, duration))
                    }
                    Err(e) => {
                        let error_msg = format!("{:?}", e);
                        eprintln!(
                            "{}",
                            json!({
                                "ts": chrono::Utc::now().to_rfc3339(),
                                "suite": "api_session_auth_integration",
                                "operation": "authenticated_request",
                                "session_id": session_id,
                                "endpoint": endpoint,
                                "duration_ms": duration.as_millis(),
                                "success": false,
                                "error": error_msg,
                                "event": "api_request_failed"
                            })
                        );

                        Err(error_msg)
                    }
                }
            }
            Err(e) => {
                let duration = start.elapsed();
                let error_msg = format!("{:?}", e);

                eprintln!(
                    "{}",
                    json!({
                        "ts": chrono::Utc::now().to_rfc3339(),
                        "suite": "api_session_auth_integration",
                        "operation": "authentication_failed",
                        "session_id": session_id,
                        "endpoint": endpoint,
                        "duration_ms": duration.as_millis(),
                        "error": error_msg,
                        "event": "auth_failed"
                    })
                );

                Err(error_msg)
            }
        }
    }

    async fn terminate_session(&mut self, session_id: &str) -> Result<Duration, String> {
        let start = Instant::now();
        let mut session_manager = self.session_manager.write().await;

        let result = session_manager.terminate_session(session_id).await;
        let duration = start.elapsed();

        match result {
            Ok(_) => {
                eprintln!(
                    "{}",
                    json!({
                        "ts": chrono::Utc::now().to_rfc3339(),
                        "suite": "api_session_auth_integration",
                        "operation": "terminate_session",
                        "session_id": session_id,
                        "duration_ms": duration.as_millis(),
                        "success": true,
                        "event": "session_terminated"
                    })
                );

                Ok(duration)
            }
            Err(e) => {
                let error_msg = format!("{:?}", e);
                eprintln!(
                    "{}",
                    json!({
                        "ts": chrono::Utc::now().to_rfc3339(),
                        "suite": "api_session_auth_integration",
                        "operation": "terminate_session",
                        "session_id": session_id,
                        "duration_ms": duration.as_millis(),
                        "success": false,
                        "error": error_msg,
                        "event": "session_termination_failed"
                    })
                );

                Err(error_msg)
            }
        }
    }

    fn compute_transcript_hash(&self, transcript: &str) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(b"test_transcript_key").expect("Valid HMAC key");
        mac.update(b"session_auth_handshake_v1:");
        mac.update(transcript.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    async fn concurrent_session_stress_test(
        &mut self,
        concurrent_clients: usize,
        requests_per_client: usize,
    ) -> Vec<Result<Duration, String>> {
        let semaphore = Arc::new(Semaphore::new(50)); // Limit concurrency
        let mut handles = Vec::new();

        for client_idx in 0..concurrent_clients {
            let client_id = format!("stress-client-{}", client_idx);
            let session_manager = self.session_manager.clone();
            let auth_middleware = self.auth_middleware.clone();
            let api_service = self.api_service.clone();
            let sem = semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let start = Instant::now();

                // Establish session
                let mut sm = session_manager.write().await;
                let handshake_data = format!("stress-handshake-{}", client_id);
                let transcript_hash = {
                    let mut mac =
                        HmacSha256::new_from_slice(b"stress_test_key").expect("Valid HMAC key");
                    mac.update(b"session_auth_handshake_v1:");
                    mac.update(handshake_data.as_bytes());
                    mac.finalize().into_bytes().to_vec()
                };

                let session_result = sm
                    .establish_session(&client_id, &transcript_hash, Duration::from_secs(300))
                    .await;
                drop(sm); // Release write lock

                match session_result {
                    Ok(session_id) => {
                        // Make multiple authenticated requests
                        for req_idx in 0..requests_per_client {
                            let endpoint = format!("/api/test-endpoint-{}", req_idx);
                            let payload =
                                format!("{{\"test\": \"data\", \"request\": {}}}", req_idx);

                            let auth_result = auth_middleware
                                .authenticate_request(&session_id, &endpoint, payload.as_bytes())
                                .await;
                            if let Ok(auth_context) = auth_result {
                                let _api_result = api_service
                                    .process_authenticated_request(
                                        &auth_context,
                                        &endpoint,
                                        &payload,
                                    )
                                    .await;
                            }

                            // Small delay to allow for race condition detection
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }

                        // Terminate session
                        let mut sm = session_manager.write().await;
                        let _terminate_result = sm.terminate_session(&session_id).await;

                        Ok(start.elapsed())
                    }
                    Err(e) => Err(format!("Client {} failed: {:?}", client_id, e)),
                }
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(format!("Task panicked: {}", e))),
            }
        }

        results
    }

    fn export_auth_performance_summary(&self) -> serde_json::Value {
        let total_duration = self.test_start.elapsed();
        let successful_auths = self.auth_logs.iter().filter(|log| log.success).count();
        let failed_auths = self.auth_logs.iter().filter(|log| !log.success).count();

        let avg_auth_duration: f64 = if !self.auth_logs.is_empty() {
            self.auth_logs
                .iter()
                .map(|log| log.duration_ms)
                .sum::<u64>() as f64
                / self.auth_logs.len() as f64
        } else {
            0.0
        };

        let max_concurrent = self
            .auth_logs
            .iter()
            .map(|log| log.concurrent_sessions)
            .max()
            .unwrap_or(0);

        json!({
            "suite": "api_session_auth_integration",
            "total_duration_ms": total_duration.as_millis(),
            "successful_authentications": successful_auths,
            "failed_authentications": failed_auths,
            "avg_auth_duration_ms": avg_auth_duration,
            "max_concurrent_sessions": max_concurrent,
            "auth_operations_per_second": successful_auths as f64 / total_duration.as_secs_f64(),
            "auth_logs_count": self.auth_logs.len(),
        })
    }
}

#[tokio::test]
async fn test_session_authenticated_api_end_to_end_real_auth() {
    let mut harness = ApiSessionAuthTestHarness::new().await;

    // Test complete session lifecycle with real authentication
    let client_id = "test-client-001";

    // Establish authenticated session
    let (session_id, establish_duration) = harness
        .establish_authenticated_session(client_id)
        .await
        .expect("Session establishment should succeed");

    assert!(
        establish_duration >= Duration::from_micros(100),
        "Auth should take realistic time"
    );
    assert!(
        establish_duration <= Duration::from_secs(5),
        "Auth should not take too long"
    );

    // Make authenticated API requests
    let test_endpoints = vec![
        ("/api/fleet/status", "{\"query\": \"status\"}"),
        ("/api/trust/verify", "{\"card_id\": \"test-card-001\"}"),
        (
            "/api/remote/capabilities",
            "{\"connector_id\": \"test-connector\"}",
        ),
    ];

    for (endpoint, payload) in test_endpoints {
        let (response, request_duration) = harness
            .authenticated_api_request(&session_id, endpoint, payload)
            .await
            .expect("Authenticated API request should succeed");

        assert!(!response.is_empty(), "API response should not be empty");
        assert!(
            request_duration <= Duration::from_secs(10),
            "API request should complete in reasonable time"
        );
    }

    // Terminate session
    let terminate_duration = harness
        .terminate_session(&session_id)
        .await
        .expect("Session termination should succeed");

    assert!(
        terminate_duration <= Duration::from_secs(1),
        "Session termination should be fast"
    );

    eprintln!("{}", harness.export_auth_performance_summary());
}

#[tokio::test]
async fn test_concurrent_session_authentication_under_load() {
    let mut harness = ApiSessionAuthTestHarness::new().await;

    // Stress test with concurrent sessions
    const CONCURRENT_CLIENTS: usize = 25;
    const REQUESTS_PER_CLIENT: usize = 10;

    let stress_results = harness
        .concurrent_session_stress_test(CONCURRENT_CLIENTS, REQUESTS_PER_CLIENT)
        .await;

    let successful = stress_results.iter().filter(|r| r.is_ok()).count();
    let failed = stress_results.iter().filter(|r| r.is_err()).count();

    eprintln!(
        "{}",
        json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "suite": "api_session_auth_integration",
            "test": "concurrent_stress",
            "concurrent_clients": CONCURRENT_CLIENTS,
            "requests_per_client": REQUESTS_PER_CLIENT,
            "successful_clients": successful,
            "failed_clients": failed,
            "success_rate": successful as f64 / stress_results.len() as f64,
            "event": "stress_test_summary"
        })
    );

    // At least 90% success rate under concurrent load
    let success_rate = successful as f64 / stress_results.len() as f64;
    assert!(
        success_rate >= 0.9,
        "Success rate too low under load: {:.2}%, expected >= 90%",
        success_rate * 100.0
    );

    eprintln!("{}", harness.export_auth_performance_summary());
}

#[tokio::test]
async fn test_session_auth_error_paths_real_failures() {
    let mut harness = ApiSessionAuthTestHarness::new().await;

    // Test error scenarios with real authentication failures
    let error_scenarios = vec![
        ("invalid_transcript", "client-invalid-001"),
        ("expired_session", "client-expired-001"),
        ("malformed_request", "client-malformed-001"),
        ("double_termination", "client-double-001"),
    ];

    for (scenario, client_id) in error_scenarios {
        match scenario {
            "invalid_transcript" => {
                // Use incorrect HMAC key to simulate authentication failure
                let mut session_manager = harness.session_manager.write().await;
                let bad_transcript = vec![0u8; 32]; // Invalid transcript hash

                let result = session_manager
                    .establish_session(client_id, &bad_transcript, Duration::from_secs(3600))
                    .await;
                assert!(
                    result.is_err(),
                    "Invalid transcript should fail authentication"
                );
            }
            "expired_session" => {
                // Establish session with very short timeout
                let (session_id, _) = harness
                    .establish_authenticated_session(client_id)
                    .await
                    .expect("Session establishment should succeed");

                // Wait for expiry (simulate by forcing expiry)
                let mut session_manager = harness.session_manager.write().await;
                session_manager
                    .expire_session(&session_id)
                    .await
                    .expect("Session expiry should succeed");
                drop(session_manager);

                // Try to use expired session
                let result = harness
                    .authenticated_api_request(&session_id, "/api/test", "{}")
                    .await;
                assert!(
                    result.is_err(),
                    "Expired session should fail authentication"
                );
            }
            "malformed_request" => {
                let (session_id, _) = harness
                    .establish_authenticated_session(client_id)
                    .await
                    .expect("Session establishment should succeed");

                // Send malformed request
                let result = harness
                    .authenticated_api_request(&session_id, "", "invalid-json{")
                    .await;
                assert!(result.is_err(), "Malformed request should fail");
            }
            "double_termination" => {
                let (session_id, _) = harness
                    .establish_authenticated_session(client_id)
                    .await
                    .expect("Session establishment should succeed");

                // First termination should succeed
                let first_result = harness.terminate_session(&session_id).await;
                assert!(first_result.is_ok(), "First termination should succeed");

                // Second termination should fail gracefully
                let second_result = harness.terminate_session(&session_id).await;
                assert!(second_result.is_err(), "Second termination should fail");
            }
            _ => {}
        }

        eprintln!(
            "{}",
            json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "suite": "api_session_auth_integration",
                "test": "error_scenarios",
                "scenario": scenario,
                "client_id": client_id,
                "expected_failure": true,
                "event": "error_scenario_tested"
            })
        );
    }

    eprintln!("{}", harness.export_auth_performance_summary());
}

#[tokio::test]
async fn test_session_state_machine_transitions_real_components() {
    let mut harness = ApiSessionAuthTestHarness::new().await;
    let client_id = "state-machine-001";

    // Test session state transitions with real state management
    let (session_id, _) = harness
        .establish_authenticated_session(client_id)
        .await
        .expect("Session establishment should succeed");

    let session_manager = harness.session_manager.read().await;
    let initial_state = session_manager
        .get_session_state(&session_id)
        .await
        .expect("Session should exist");

    assert_eq!(
        initial_state,
        SessionState::Active,
        "New session should be Active"
    );
    drop(session_manager);

    // Test state transitions
    let state_transitions = vec![
        (SessionState::Active, "active session operations"),
        (SessionState::Terminating, "graceful shutdown"),
        (SessionState::Terminated, "final state"),
    ];

    for (target_state, description) in state_transitions {
        let start = Instant::now();

        let mut session_manager = harness.session_manager.write().await;
        let transition_result = match target_state {
            SessionState::Terminating => {
                session_manager.begin_session_termination(&session_id).await
            }
            SessionState::Terminated => session_manager.terminate_session(&session_id).await,
            _ => Ok(()),
        };
        drop(session_manager);

        let duration = start.elapsed();

        eprintln!(
            "{}",
            json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "suite": "api_session_auth_integration",
                "test": "state_transitions",
                "session_id": session_id,
                "target_state": format!("{:?}", target_state),
                "description": description,
                "duration_ms": duration.as_millis(),
                "success": transition_result.is_ok(),
                "event": "state_transition"
            })
        );

        if target_state != SessionState::Terminated {
            assert!(
                transition_result.is_ok(),
                "State transition should succeed for {}",
                description
            );
        }
    }

    eprintln!("{}", harness.export_auth_performance_summary());
}
