use frankenengine_node::api::session_auth::{
    MessageDirection, SessionConfig, SessionError, SessionManager, SessionState, event_codes,
    sign_handshake, sign_session_message,
};
use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use frankenengine_node::control_plane::key_role_separation::{KeyRole, KeyRoleRegistry};
use frankenengine_node::security::epoch_scoped_keys::RootSecret;

const SESSION_ID: &str = "jcq1z-session";
const CLIENT_ID: &str = "client-jcq1z";
const SERVER_ID: &str = "server-jcq1z";
const ENC_KEY: &str = "enc-jcq1z";
const SIGN_KEY: &str = "sign-jcq1z";
const TRACE_ID: &str = "trace-jcq1z";
const ESTABLISHED_AT: u64 = 10_000;

fn root_secret() -> RootSecret {
    RootSecret::from_bytes([0x6C; 32])
}

fn epoch() -> ControlEpoch {
    ControlEpoch::from(29_u64)
}

fn config(max_sessions: usize) -> SessionConfig {
    SessionConfig {
        replay_window: 0,
        max_sessions,
        session_timeout_ms: 60_000,
    }
}

fn key_registry() -> KeyRoleRegistry {
    let mut registry = KeyRoleRegistry::new();
    registry
        .bind(
            ENC_KEY,
            KeyRole::Encryption,
            vec![0xE1; 32],
            "bd-jcq1z.2.1",
            0,
            120_000,
            "trace-bind-enc-jcq1z",
        )
        .expect("bind encryption key");
    registry
        .bind(
            SIGN_KEY,
            KeyRole::Signing,
            vec![0x51; 32],
            "bd-jcq1z.2.1",
            0,
            120_000,
            "trace-bind-sign-jcq1z",
        )
        .expect("bind signing key");
    registry
}

fn manager(max_sessions: usize) -> SessionManager {
    SessionManager::with_key_role_registry(
        config(max_sessions),
        root_secret(),
        epoch(),
        key_registry(),
    )
}

fn handshake_mac(session_id: &str, timestamp: u64) -> [u8; 32] {
    sign_handshake(
        session_id,
        CLIENT_ID,
        SERVER_ID,
        ENC_KEY,
        SIGN_KEY,
        epoch(),
        timestamp,
        &root_secret(),
    )
}

fn establish(
    manager: &mut SessionManager,
    session_id: &str,
    timestamp: u64,
) -> Result<(), SessionError> {
    manager
        .establish_session(
            session_id.to_string(),
            CLIENT_ID.to_string(),
            SERVER_ID.to_string(),
            ENC_KEY.to_string(),
            SIGN_KEY.to_string(),
            timestamp,
            format!("{TRACE_ID}-{session_id}"),
            handshake_mac(session_id, timestamp),
        )
        .map(|_| ())
}

fn message_mac(
    manager: &SessionManager,
    session_id: &str,
    direction: MessageDirection,
    sequence: u64,
    payload_hash: &str,
) -> [u8; 32] {
    let session = manager
        .get_session(session_id)
        .expect("session must exist before signing messages");
    sign_session_message(
        session_id,
        direction,
        sequence,
        payload_hash,
        epoch(),
        &session.handshake_mac,
        &root_secret(),
    )
}

#[test]
fn replacement_executes_real_signed_session_lifecycle() {
    let mut manager = manager(4);

    establish(&mut manager, SESSION_ID, ESTABLISHED_AT).expect("valid signed handshake");

    let session = manager.get_session(SESSION_ID).expect("session stored");
    assert_eq!(session.state, SessionState::Active);
    assert_eq!(manager.active_session_count(), 1);

    let send_payload = "sha256:send-payload-jcq1z";
    let send_mac = message_mac(
        &manager,
        SESSION_ID,
        MessageDirection::Send,
        0,
        send_payload,
    );
    let send = manager
        .process_message(
            SESSION_ID,
            MessageDirection::Send,
            0,
            send_payload,
            &send_mac,
            ESTABLISHED_AT + 10,
            "trace-send-jcq1z",
        )
        .expect("signed send message accepted");
    assert_eq!(send.sequence, 0);

    let recv_payload = "sha256:recv-payload-jcq1z";
    let recv_mac = message_mac(
        &manager,
        SESSION_ID,
        MessageDirection::Receive,
        0,
        recv_payload,
    );
    let recv = manager
        .process_message(
            SESSION_ID,
            MessageDirection::Receive,
            0,
            recv_payload,
            &recv_mac,
            ESTABLISHED_AT + 20,
            "trace-recv-jcq1z",
        )
        .expect("signed receive message accepted");
    assert_eq!(recv.sequence, 0);

    manager
        .terminate_session(SESSION_ID, ESTABLISHED_AT + 30, "trace-term-jcq1z")
        .expect("termination succeeds");
    assert_eq!(
        manager
            .get_session(SESSION_ID)
            .expect("session retained")
            .state,
        SessionState::Terminated
    );

    let event_codes: Vec<&str> = manager
        .events()
        .iter()
        .map(|event| event.event_code.as_str())
        .collect();
    assert_eq!(
        event_codes,
        vec![
            event_codes::SCC_SESSION_ESTABLISHED,
            event_codes::SCC_MESSAGE_ACCEPTED,
            event_codes::SCC_MESSAGE_ACCEPTED,
            event_codes::SCC_SESSION_TERMINATED,
        ]
    );
}

#[test]
fn replacement_rejects_tampered_handshake_transcript() {
    let mut manager = manager(4);
    let bad_mac = handshake_mac("tampered-session", ESTABLISHED_AT);

    let err = manager
        .establish_session(
            SESSION_ID.to_string(),
            CLIENT_ID.to_string(),
            SERVER_ID.to_string(),
            ENC_KEY.to_string(),
            SIGN_KEY.to_string(),
            ESTABLISHED_AT,
            "trace-bad-handshake-jcq1z".to_string(),
            bad_mac,
        )
        .expect_err("tampered handshake must fail");

    assert!(matches!(err, SessionError::AuthFailed { .. }));
    assert!(manager.get_session(SESSION_ID).is_none());
    assert!(
        manager
            .events()
            .iter()
            .any(|event| event.event_code == event_codes::SCC_MESSAGE_REJECTED)
    );
}

#[test]
fn replacement_enforces_capacity_and_terminated_session_denial() {
    let mut manager = manager(1);
    establish(&mut manager, "session-one", ESTABLISHED_AT).expect("first session accepted");

    let capacity_err = establish(&mut manager, "session-two", ESTABLISHED_AT + 1)
        .expect_err("second live session must exceed max_sessions=1");
    assert!(matches!(
        capacity_err,
        SessionError::MaxSessionsReached { limit: 1 }
    ));

    manager
        .terminate_session("session-one", ESTABLISHED_AT + 2, "trace-term-capacity")
        .expect("terminate first session");
    let mac = message_mac(
        &manager,
        "session-one",
        MessageDirection::Send,
        0,
        "sha256:after-terminate",
    );
    let terminated = manager
        .process_message(
            "session-one",
            MessageDirection::Send,
            0,
            "sha256:after-terminate",
            &mac,
            ESTABLISHED_AT + 3,
            "trace-after-term",
        )
        .expect_err("terminated session cannot accept messages");
    assert!(matches!(terminated, SessionError::SessionTerminated { .. }));
}

#[test]
fn replacement_rejects_message_mac_and_sequence_replay() {
    let mut manager = manager(4);
    establish(&mut manager, SESSION_ID, ESTABLISHED_AT).expect("valid signed handshake");

    let payload = "sha256:first-message";
    let mac = message_mac(&manager, SESSION_ID, MessageDirection::Send, 0, payload);
    manager
        .process_message(
            SESSION_ID,
            MessageDirection::Send,
            0,
            payload,
            &mac,
            ESTABLISHED_AT + 10,
            "trace-first-message",
        )
        .expect("first message accepted");

    let replay = manager
        .process_message(
            SESSION_ID,
            MessageDirection::Send,
            0,
            payload,
            &mac,
            ESTABLISHED_AT + 20,
            "trace-replay-message",
        )
        .expect_err("strict sequence mode rejects replay");
    assert!(matches!(replay, SessionError::SequenceViolation { .. }));

    let mut bad_mac = message_mac(
        &manager,
        SESSION_ID,
        MessageDirection::Send,
        1,
        "sha256:second-message",
    );
    bad_mac[0] ^= 0xFF;
    let auth_failed = manager
        .process_message(
            SESSION_ID,
            MessageDirection::Send,
            1,
            "sha256:second-message",
            &bad_mac,
            ESTABLISHED_AT + 30,
            "trace-bad-message-mac",
        )
        .expect_err("tampered message MAC must fail before acceptance");
    assert!(matches!(auth_failed, SessionError::AuthFailed { .. }));
}
