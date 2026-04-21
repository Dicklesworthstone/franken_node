use frankenengine_node::api::session_auth::{
    MessageDirection, SessionConfig, SessionError, SessionLifecycleMessage,
    SessionLifecycleScenario, demo_session_lifecycle, demo_windowed_replay, event_codes,
    session_lifecycle_events,
};
use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use frankenengine_node::security::epoch_scoped_keys::RootSecret;

fn lifecycle_scenario(max_sessions: usize) -> SessionLifecycleScenario {
    SessionLifecycleScenario {
        config: SessionConfig {
            replay_window: 0,
            max_sessions,
            session_timeout_ms: 60_000,
        },
        root_secret: RootSecret::from_bytes([0x42; 32]),
        epoch: ControlEpoch::from(7u64),
        session_id: "sess-real".to_string(),
        client_identity: "client-real".to_string(),
        server_identity: "server-real".to_string(),
        encryption_key_id: "enc-real".to_string(),
        signing_key_id: "sign-real".to_string(),
        established_at: 10_000,
        trace_id: "trace-real".to_string(),
        messages: vec![
            SessionLifecycleMessage {
                direction: MessageDirection::Send,
                sequence: 0,
                payload_hash: "payload-send-0".to_string(),
                timestamp: 10_100,
            },
            SessionLifecycleMessage {
                direction: MessageDirection::Receive,
                sequence: 0,
                payload_hash: "payload-recv-0".to_string(),
                timestamp: 10_200,
            },
        ],
        terminate_at: Some(10_300),
    }
}

#[test]
fn caller_supplied_lifecycle_emits_events() {
    let events = session_lifecycle_events(lifecycle_scenario(4))
        .expect("caller supplied lifecycle should execute");

    assert_eq!(events.len(), 4);
    assert_eq!(events[0].event_code, event_codes::SCC_SESSION_ESTABLISHED);
    assert_eq!(events[1].event_code, event_codes::SCC_MESSAGE_ACCEPTED);
    assert_eq!(events[2].event_code, event_codes::SCC_MESSAGE_ACCEPTED);
    assert_eq!(events[3].event_code, event_codes::SCC_SESSION_TERMINATED);
    assert!(events.iter().all(|event| event.session_id == "sess-real"));
}

#[test]
fn caller_supplied_lifecycle_propagates_typed_errors() {
    let err = session_lifecycle_events(lifecycle_scenario(0))
        .expect_err("max_sessions=0 must fail closed instead of producing demo events");

    assert!(matches!(err, SessionError::MaxSessionsReached { limit: 0 }));
}

#[test]
fn deterministic_fixture_wrappers_remain_test_support_only() {
    let lifecycle_events = demo_session_lifecycle();
    assert_eq!(lifecycle_events.len(), 7);
    assert_eq!(
        lifecycle_events[0].event_code,
        event_codes::SCC_SESSION_ESTABLISHED
    );

    let replay_events = demo_windowed_replay();
    let rejected = replay_events
        .iter()
        .filter(|event| event.event_code == event_codes::SCC_MESSAGE_REJECTED)
        .count();
    assert_eq!(rejected, 1);
}
