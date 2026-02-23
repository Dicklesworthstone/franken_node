//! bd-oty: Session-authenticated control channel integration.
//!
//! Integrates the canonical ControlChannel (bd-v97o) and KeyRoleRegistry
//! (bd-364) into a unified session management layer wrapping all control
//! API endpoints.
//!
//! # Invariants
//!
//! - INV-SCC-SESSION-AUTH: Every control message requires an active
//!   authenticated session.
//! - INV-SCC-MONOTONIC: Per-direction sequence numbers are strictly monotonic.
//! - INV-SCC-ROLE-KEYS: Session uses Encryption key for exchange, Signing key
//!   for auth.
//! - INV-SCC-TERMINATED: Terminated sessions reject all further messages.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::connector::control_channel::Direction;
use crate::control_plane::key_role_separation::KeyRole;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Stable event codes for session-authenticated control channel.
pub mod event_codes {
    /// Session successfully established.
    pub const SCC_SESSION_ESTABLISHED: &str = "SCC-001";
    /// Authenticated message accepted.
    pub const SCC_MESSAGE_ACCEPTED: &str = "SCC-002";
    /// Message rejected (sequence/replay/auth).
    pub const SCC_MESSAGE_REJECTED: &str = "SCC-003";
    /// Session terminated.
    pub const SCC_SESSION_TERMINATED: &str = "SCC-004";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Stable error codes for session-authenticated control channel.
pub mod error_codes {
    pub const ERR_SCC_NO_SESSION: &str = "ERR_SCC_NO_SESSION";
    pub const ERR_SCC_SEQUENCE_VIOLATION: &str = "ERR_SCC_SEQUENCE_VIOLATION";
    pub const ERR_SCC_SESSION_TERMINATED: &str = "ERR_SCC_SESSION_TERMINATED";
    pub const ERR_SCC_ROLE_MISMATCH: &str = "ERR_SCC_ROLE_MISMATCH";
    pub const ERR_SCC_AUTH_FAILED: &str = "ERR_SCC_AUTH_FAILED";
    pub const ERR_SCC_MAX_SESSIONS: &str = "ERR_SCC_MAX_SESSIONS";
}

// ---------------------------------------------------------------------------
// SessionState
// ---------------------------------------------------------------------------

/// Lifecycle state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionState {
    /// Handshake in progress.
    Establishing,
    /// Session authenticated, traffic flowing.
    Active,
    /// Graceful shutdown in progress.
    Terminating,
    /// Session closed.
    Terminated,
}

impl SessionState {
    /// Label for structured logging.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Establishing => "establishing",
            Self::Active => "active",
            Self::Terminating => "terminating",
            Self::Terminated => "terminated",
        }
    }

    /// Whether the session can accept messages.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

// ---------------------------------------------------------------------------
// SessionConfig
// ---------------------------------------------------------------------------

/// Configuration for the session manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Replay window size (0 = strict monotonicity).
    pub replay_window: u64,
    /// Maximum concurrent sessions.
    pub max_sessions: usize,
    /// Session inactivity timeout in milliseconds.
    pub session_timeout_ms: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            replay_window: 0,
            max_sessions: 256,
            session_timeout_ms: 300_000, // 5 minutes
        }
    }
}

// ---------------------------------------------------------------------------
// AuthenticatedSession
// ---------------------------------------------------------------------------

/// An authenticated control session binding identity, keys, and sequence state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedSession {
    /// Unique session identifier.
    pub session_id: String,
    /// Current lifecycle state.
    pub state: SessionState,
    /// Authenticated client principal.
    pub client_identity: String,
    /// Server identity.
    pub server_identity: String,
    /// Key bound to Encryption role.
    pub encryption_key_id: String,
    /// Key bound to Signing role.
    pub signing_key_id: String,
    /// UTC timestamp (ms) when session was established.
    pub established_at: u64,
    /// Next outbound sequence number.
    pub send_seq: u64,
    /// Next inbound sequence number.
    pub recv_seq: u64,
    /// Configured replay window size.
    pub replay_window: u64,
}

impl AuthenticatedSession {
    /// Create a new session in the Establishing state.
    pub fn new(
        session_id: String,
        client_identity: String,
        server_identity: String,
        encryption_key_id: String,
        signing_key_id: String,
        replay_window: u64,
    ) -> Self {
        Self {
            session_id,
            state: SessionState::Establishing,
            client_identity,
            server_identity,
            encryption_key_id,
            signing_key_id,
            established_at: 0,
            send_seq: 0,
            recv_seq: 0,
            replay_window,
        }
    }

    /// Transition to Active state with the given timestamp.
    pub fn activate(&mut self, timestamp: u64) {
        self.state = SessionState::Active;
        self.established_at = timestamp;
    }

    /// Transition to Terminating state.
    pub fn begin_termination(&mut self) {
        self.state = SessionState::Terminating;
    }

    /// Transition to Terminated state.
    pub fn terminate(&mut self) {
        self.state = SessionState::Terminated;
    }

    /// Advance send sequence and return the assigned number.
    pub fn next_send_seq(&mut self) -> u64 {
        let seq = self.send_seq;
        self.send_seq += 1;
        seq
    }

    /// Advance recv sequence and return the assigned number.
    pub fn next_recv_seq(&mut self) -> u64 {
        let seq = self.recv_seq;
        self.recv_seq += 1;
        seq
    }
}

// ---------------------------------------------------------------------------
// AuthenticatedMessage
// ---------------------------------------------------------------------------

/// A message authenticated within a session context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedMessage {
    /// Owning session.
    pub session_id: String,
    /// Per-direction monotonic sequence number.
    pub sequence: u64,
    /// Send or Receive.
    pub direction: MessageDirection,
    /// SHA-256 of payload.
    pub payload_hash: String,
    /// Signature using Signing role key.
    pub signature: String,
}

/// Direction of an authenticated message. Maps to connector::Direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MessageDirection {
    Send,
    Receive,
}

impl MessageDirection {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Receive => "receive",
        }
    }

    /// Convert from connector Direction.
    pub fn from_control_direction(d: Direction) -> Self {
        match d {
            Direction::Send => Self::Send,
            Direction::Receive => Self::Receive,
        }
    }
}

// ---------------------------------------------------------------------------
// SessionEvent
// ---------------------------------------------------------------------------

/// Structured audit event for session operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvent {
    /// Event code (SCC-001 through SCC-004).
    pub event_code: String,
    /// Session identifier.
    pub session_id: String,
    /// Trace ID for distributed tracing.
    pub trace_id: String,
    /// Human-readable description.
    pub detail: String,
    /// Epoch timestamp in milliseconds.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// SessionError
// ---------------------------------------------------------------------------

/// Errors from session operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    NoSession {
        session_id: String,
    },
    SequenceViolation {
        session_id: String,
        direction: MessageDirection,
        expected_min: u64,
        got: u64,
    },
    SessionTerminated {
        session_id: String,
    },
    RoleMismatch {
        session_id: String,
        expected_role: String,
        actual_role: String,
    },
    AuthFailed {
        session_id: String,
        reason: String,
    },
    MaxSessionsReached {
        limit: usize,
    },
    ReplayDetected {
        session_id: String,
        direction: MessageDirection,
        sequence: u64,
    },
}

impl SessionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoSession { .. } => error_codes::ERR_SCC_NO_SESSION,
            Self::SequenceViolation { .. } => error_codes::ERR_SCC_SEQUENCE_VIOLATION,
            Self::SessionTerminated { .. } => error_codes::ERR_SCC_SESSION_TERMINATED,
            Self::RoleMismatch { .. } => error_codes::ERR_SCC_ROLE_MISMATCH,
            Self::AuthFailed { .. } => error_codes::ERR_SCC_AUTH_FAILED,
            Self::MaxSessionsReached { .. } => error_codes::ERR_SCC_MAX_SESSIONS,
            Self::ReplayDetected { .. } => error_codes::ERR_SCC_SEQUENCE_VIOLATION,
        }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSession { session_id } => {
                write!(f, "no active session: {session_id}")
            }
            Self::SequenceViolation {
                session_id,
                direction,
                expected_min,
                got,
            } => {
                write!(
                    f,
                    "sequence violation on {}: session={session_id} expected>={expected_min} got={got}",
                    direction.label()
                )
            }
            Self::SessionTerminated { session_id } => {
                write!(f, "session terminated: {session_id}")
            }
            Self::RoleMismatch {
                session_id,
                expected_role,
                actual_role,
            } => {
                write!(
                    f,
                    "role mismatch: session={session_id} expected={expected_role} actual={actual_role}"
                )
            }
            Self::AuthFailed { session_id, reason } => {
                write!(f, "auth failed: session={session_id} reason={reason}")
            }
            Self::MaxSessionsReached { limit } => {
                write!(f, "max sessions reached: limit={limit}")
            }
            Self::ReplayDetected {
                session_id,
                direction,
                sequence,
            } => {
                write!(
                    f,
                    "replay detected: session={session_id} direction={} seq={sequence}",
                    direction.label()
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

/// Manages authenticated sessions with lifecycle tracking and sequence
/// enforcement.
///
/// # INV-SCC-SESSION-AUTH
/// Every control message requires an active authenticated session — the
/// `process_message` method rejects messages for non-existent or
/// non-active sessions.
///
/// # INV-SCC-MONOTONIC
/// Per-direction sequence numbers are strictly monotonic within a session.
///
/// # INV-SCC-TERMINATED
/// Once terminated, a session rejects all further messages.
pub struct SessionManager {
    config: SessionConfig,
    sessions: BTreeMap<String, AuthenticatedSession>,
    /// Per-session, per-direction replay windows (for replay_window > 0).
    replay_windows: BTreeMap<(String, MessageDirection), BTreeSet<u64>>,
    events: Vec<SessionEvent>,
}

impl SessionManager {
    /// Create a new SessionManager with the given config.
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            sessions: BTreeMap::new(),
            replay_windows: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// Create with default config.
    pub fn default_manager() -> Self {
        Self::new(SessionConfig::default())
    }

    /// Current number of active/establishing sessions.
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| matches!(s.state, SessionState::Active | SessionState::Establishing))
            .count()
    }

    /// Get config reference.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Get all events.
    pub fn events(&self) -> &[SessionEvent] {
        &self.events
    }

    /// Get a session by ID.
    pub fn get_session(&self, session_id: &str) -> Option<&AuthenticatedSession> {
        self.sessions.get(session_id)
    }

    /// List all session IDs.
    pub fn session_ids(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }

    /// Establish a new authenticated session.
    ///
    /// # INV-SCC-ROLE-KEYS
    /// Caller must supply the correct role-bound key IDs. The manager
    /// records them but the actual key-role verification is done at a
    /// higher layer (KeyRoleRegistry).
    #[allow(clippy::too_many_arguments)]
    pub fn establish_session(
        &mut self,
        session_id: String,
        client_identity: String,
        server_identity: String,
        encryption_key_id: String,
        signing_key_id: String,
        timestamp: u64,
        trace_id: String,
    ) -> Result<&AuthenticatedSession, SessionError> {
        // Check max sessions
        if self.active_session_count() >= self.config.max_sessions {
            return Err(SessionError::MaxSessionsReached {
                limit: self.config.max_sessions,
            });
        }

        let mut session = AuthenticatedSession::new(
            session_id.clone(),
            client_identity,
            server_identity,
            encryption_key_id,
            signing_key_id,
            self.config.replay_window,
        );
        session.activate(timestamp);

        self.sessions.insert(session_id.clone(), session);

        self.events.push(SessionEvent {
            event_code: event_codes::SCC_SESSION_ESTABLISHED.to_string(),
            session_id: session_id.clone(),
            trace_id,
            detail: "session established".to_string(),
            timestamp,
        });

        self.sessions
            .get(&session_id)
            .ok_or(SessionError::NoSession { session_id })
    }

    /// Process an authenticated message within a session.
    ///
    /// Enforces:
    /// - Session existence (INV-SCC-SESSION-AUTH)
    /// - Session is Active (INV-SCC-TERMINATED)
    /// - Sequence monotonicity (INV-SCC-MONOTONIC)
    /// - Replay detection for windowed mode
    #[allow(clippy::too_many_arguments)]
    pub fn process_message(
        &mut self,
        session_id: &str,
        direction: MessageDirection,
        sequence: u64,
        payload_hash: &str,
        signature: &str,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<AuthenticatedMessage, SessionError> {
        // INV-SCC-SESSION-AUTH: session must exist
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| SessionError::NoSession {
                session_id: session_id.to_string(),
            })?;

        // INV-SCC-TERMINATED: terminated sessions reject all messages
        if session.state == SessionState::Terminated {
            self.events.push(SessionEvent {
                event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                session_id: session_id.to_string(),
                trace_id: trace_id.to_string(),
                detail: "session terminated".to_string(),
                timestamp,
            });
            return Err(SessionError::SessionTerminated {
                session_id: session_id.to_string(),
            });
        }

        if session.state == SessionState::Terminating {
            self.events.push(SessionEvent {
                event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                session_id: session_id.to_string(),
                trace_id: trace_id.to_string(),
                detail: "session terminating".to_string(),
                timestamp,
            });
            return Err(SessionError::SessionTerminated {
                session_id: session_id.to_string(),
            });
        }

        if !session.state.is_active() {
            self.events.push(SessionEvent {
                event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                session_id: session_id.to_string(),
                trace_id: trace_id.to_string(),
                detail: format!("session not active: {}", session.state.label()),
                timestamp,
            });
            return Err(SessionError::NoSession {
                session_id: session_id.to_string(),
            });
        }

        // INV-SCC-MONOTONIC: check sequence monotonicity
        let expected_seq = match direction {
            MessageDirection::Send => session.send_seq,
            MessageDirection::Receive => session.recv_seq,
        };

        if self.config.replay_window == 0 {
            // Strict monotonicity: sequence must equal expected
            if sequence != expected_seq {
                self.events.push(SessionEvent {
                    event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                    session_id: session_id.to_string(),
                    trace_id: trace_id.to_string(),
                    detail: format!("sequence violation: expected={expected_seq} got={sequence}"),
                    timestamp,
                });
                return Err(SessionError::SequenceViolation {
                    session_id: session_id.to_string(),
                    direction,
                    expected_min: expected_seq,
                    got: sequence,
                });
            }
        } else {
            // Windowed mode: accept sequences within [floor, ...) where
            // floor = max(0, high_watermark - replay_window). Reject replays.
            let floor = expected_seq.saturating_sub(self.config.replay_window);

            if sequence < floor {
                self.events.push(SessionEvent {
                    event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                    session_id: session_id.to_string(),
                    trace_id: trace_id.to_string(),
                    detail: format!("sequence regress: floor={floor} got={sequence}"),
                    timestamp,
                });
                return Err(SessionError::SequenceViolation {
                    session_id: session_id.to_string(),
                    direction,
                    expected_min: floor,
                    got: sequence,
                });
            }

            let replay_key = (session_id.to_string(), direction);
            let window = self.replay_windows.entry(replay_key).or_default();

            if window.contains(&sequence) {
                self.events.push(SessionEvent {
                    event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                    session_id: session_id.to_string(),
                    trace_id: trace_id.to_string(),
                    detail: format!("replay detected: seq={sequence}"),
                    timestamp,
                });
                return Err(SessionError::ReplayDetected {
                    session_id: session_id.to_string(),
                    direction,
                    sequence,
                });
            }

            window.insert(sequence);

            // Prune entries below the sliding floor
            window.retain(|&s| s >= floor);
        }

        // Advance session sequence counter
        let session_mut =
            self.sessions
                .get_mut(session_id)
                .ok_or_else(|| SessionError::NoSession {
                    session_id: session_id.to_string(),
                })?;
        match direction {
            MessageDirection::Send => {
                if sequence >= session_mut.send_seq {
                    session_mut.send_seq = sequence + 1;
                }
            }
            MessageDirection::Receive => {
                if sequence >= session_mut.recv_seq {
                    session_mut.recv_seq = sequence + 1;
                }
            }
        }

        let msg = AuthenticatedMessage {
            session_id: session_id.to_string(),
            sequence,
            direction,
            payload_hash: payload_hash.to_string(),
            signature: signature.to_string(),
        };

        self.events.push(SessionEvent {
            event_code: event_codes::SCC_MESSAGE_ACCEPTED.to_string(),
            session_id: session_id.to_string(),
            trace_id: trace_id.to_string(),
            detail: format!("message accepted: dir={} seq={sequence}", direction.label()),
            timestamp,
        });

        Ok(msg)
    }

    /// Terminate a session.
    ///
    /// # INV-SCC-TERMINATED
    /// Moves the session to Terminated state. All subsequent messages are
    /// rejected.
    pub fn terminate_session(
        &mut self,
        session_id: &str,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<(), SessionError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NoSession {
                session_id: session_id.to_string(),
            })?;

        session.terminate();

        // Clean up replay windows
        self.replay_windows.retain(|key, _| key.0 != session_id);

        self.events.push(SessionEvent {
            event_code: event_codes::SCC_SESSION_TERMINATED.to_string(),
            session_id: session_id.to_string(),
            trace_id: trace_id.to_string(),
            detail: "session terminated".to_string(),
            timestamp,
        });

        Ok(())
    }

    /// Validate that the provided key roles match expectations.
    ///
    /// # INV-SCC-ROLE-KEYS
    /// Session establishment must use Encryption key for key exchange
    /// and Signing key for authentication.
    pub fn validate_key_roles(
        encryption_role: KeyRole,
        signing_role: KeyRole,
    ) -> Result<(), SessionError> {
        if encryption_role != KeyRole::Encryption {
            return Err(SessionError::RoleMismatch {
                session_id: String::new(),
                expected_role: "Encryption".to_string(),
                actual_role: format!("{encryption_role:?}"),
            });
        }
        if signing_role != KeyRole::Signing {
            return Err(SessionError::RoleMismatch {
                session_id: String::new(),
                expected_role: "Signing".to_string(),
                actual_role: format!("{signing_role:?}"),
            });
        }
        Ok(())
    }
}

/// Demonstrate session lifecycle with strict monotonicity.
pub fn demo_session_lifecycle() -> Vec<SessionEvent> {
    let config = SessionConfig {
        replay_window: 0,
        max_sessions: 10,
        session_timeout_ms: 60_000,
    };
    let mut mgr = SessionManager::new(config);

    // Establish session
    let _ = mgr.establish_session(
        "sess-001".into(),
        "client-a".into(),
        "server-1".into(),
        "enc-key-001".into(),
        "sign-key-001".into(),
        1_000_000,
        "trace-001".into(),
    );

    // Send 3 messages with strict monotonicity
    for seq in 0..3 {
        let _ = mgr.process_message(
            "sess-001",
            MessageDirection::Send,
            seq,
            &format!("hash-{seq}"),
            &format!("sig-{seq}"),
            1_000_000 + seq * 100,
            "trace-001",
        );
    }

    // Receive 2 messages
    for seq in 0..2 {
        let _ = mgr.process_message(
            "sess-001",
            MessageDirection::Receive,
            seq,
            &format!("recv-hash-{seq}"),
            &format!("recv-sig-{seq}"),
            1_000_200 + seq * 100,
            "trace-001",
        );
    }

    // Terminate
    let _ = mgr.terminate_session("sess-001", 1_001_000, "trace-001");

    mgr.events().to_vec()
}

/// Demonstrate windowed replay detection.
pub fn demo_windowed_replay() -> Vec<SessionEvent> {
    let config = SessionConfig {
        replay_window: 4,
        max_sessions: 10,
        session_timeout_ms: 60_000,
    };
    let mut mgr = SessionManager::new(config);

    let _ = mgr.establish_session(
        "sess-win".into(),
        "client-b".into(),
        "server-2".into(),
        "enc-key-002".into(),
        "sign-key-002".into(),
        2_000_000,
        "trace-002".into(),
    );

    // Send out-of-order within window
    let _ = mgr.process_message(
        "sess-win",
        MessageDirection::Send,
        0,
        "hash-0",
        "sig-0",
        2_000_100,
        "trace-002",
    );
    let _ = mgr.process_message(
        "sess-win",
        MessageDirection::Send,
        2,
        "hash-2",
        "sig-2",
        2_000_200,
        "trace-002",
    );
    let _ = mgr.process_message(
        "sess-win",
        MessageDirection::Send,
        1,
        "hash-1",
        "sig-1",
        2_000_300,
        "trace-002",
    );

    // Attempt replay of seq 2 — should be rejected
    let _ = mgr.process_message(
        "sess-win",
        MessageDirection::Send,
        2,
        "hash-2-dup",
        "sig-2-dup",
        2_000_400,
        "trace-002",
    );

    let _ = mgr.terminate_session("sess-win", 2_001_000, "trace-002");

    mgr.events().to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_manager() -> SessionManager {
        SessionManager::new(SessionConfig {
            replay_window: 0,
            max_sessions: 10,
            session_timeout_ms: 60_000,
        })
    }

    fn establish_test_session(mgr: &mut SessionManager, sid: &str) {
        mgr.establish_session(
            sid.to_string(),
            "client-a".into(),
            "server-1".into(),
            "enc-key".into(),
            "sign-key".into(),
            1_000_000,
            "trace-test".into(),
        )
        .unwrap();
    }

    // ── SessionState tests ──────────────────────────────────────────

    #[test]
    fn test_session_state_labels() {
        assert_eq!(SessionState::Establishing.label(), "establishing");
        assert_eq!(SessionState::Active.label(), "active");
        assert_eq!(SessionState::Terminating.label(), "terminating");
        assert_eq!(SessionState::Terminated.label(), "terminated");
    }

    #[test]
    fn test_session_state_is_active() {
        assert!(!SessionState::Establishing.is_active());
        assert!(SessionState::Active.is_active());
        assert!(!SessionState::Terminating.is_active());
        assert!(!SessionState::Terminated.is_active());
    }

    // ── SessionConfig tests ─────────────────────────────────────────

    #[test]
    fn test_default_config() {
        let cfg = SessionConfig::default();
        assert_eq!(cfg.replay_window, 0);
        assert_eq!(cfg.max_sessions, 256);
        assert_eq!(cfg.session_timeout_ms, 300_000);
    }

    // ── AuthenticatedSession tests ──────────────────────────────────

    #[test]
    fn test_session_new_is_establishing() {
        let s = AuthenticatedSession::new(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "sg".into(),
            0,
        );
        assert_eq!(s.state, SessionState::Establishing);
        assert_eq!(s.send_seq, 0);
        assert_eq!(s.recv_seq, 0);
    }

    #[test]
    fn test_session_activate() {
        let mut s = AuthenticatedSession::new(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "sg".into(),
            0,
        );
        s.activate(42);
        assert_eq!(s.state, SessionState::Active);
        assert_eq!(s.established_at, 42);
    }

    #[test]
    fn test_session_lifecycle_transitions() {
        let mut s = AuthenticatedSession::new(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "sg".into(),
            0,
        );
        s.activate(1);
        assert_eq!(s.state, SessionState::Active);
        s.begin_termination();
        assert_eq!(s.state, SessionState::Terminating);
        s.terminate();
        assert_eq!(s.state, SessionState::Terminated);
    }

    #[test]
    fn test_next_send_seq_monotonic() {
        let mut s = AuthenticatedSession::new(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "sg".into(),
            0,
        );
        assert_eq!(s.next_send_seq(), 0);
        assert_eq!(s.next_send_seq(), 1);
        assert_eq!(s.next_send_seq(), 2);
    }

    #[test]
    fn test_next_recv_seq_monotonic() {
        let mut s = AuthenticatedSession::new(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "sg".into(),
            0,
        );
        assert_eq!(s.next_recv_seq(), 0);
        assert_eq!(s.next_recv_seq(), 1);
    }

    // ── MessageDirection tests ──────────────────────────────────────

    #[test]
    fn test_message_direction_labels() {
        assert_eq!(MessageDirection::Send.label(), "send");
        assert_eq!(MessageDirection::Receive.label(), "receive");
    }

    #[test]
    fn test_from_control_direction() {
        assert_eq!(
            MessageDirection::from_control_direction(Direction::Send),
            MessageDirection::Send
        );
        assert_eq!(
            MessageDirection::from_control_direction(Direction::Receive),
            MessageDirection::Receive
        );
    }

    // ── SessionError tests ──────────────────────────────────────────

    #[test]
    fn test_error_codes() {
        let e1 = SessionError::NoSession {
            session_id: "s".into(),
        };
        assert_eq!(e1.code(), "ERR_SCC_NO_SESSION");

        let e2 = SessionError::SequenceViolation {
            session_id: "s".into(),
            direction: MessageDirection::Send,
            expected_min: 5,
            got: 3,
        };
        assert_eq!(e2.code(), "ERR_SCC_SEQUENCE_VIOLATION");

        let e3 = SessionError::SessionTerminated {
            session_id: "s".into(),
        };
        assert_eq!(e3.code(), "ERR_SCC_SESSION_TERMINATED");

        let e4 = SessionError::RoleMismatch {
            session_id: "s".into(),
            expected_role: "Signing".into(),
            actual_role: "Encryption".into(),
        };
        assert_eq!(e4.code(), "ERR_SCC_ROLE_MISMATCH");

        let e5 = SessionError::AuthFailed {
            session_id: "s".into(),
            reason: "bad sig".into(),
        };
        assert_eq!(e5.code(), "ERR_SCC_AUTH_FAILED");

        let e6 = SessionError::MaxSessionsReached { limit: 10 };
        assert_eq!(e6.code(), "ERR_SCC_MAX_SESSIONS");
    }

    #[test]
    fn test_error_display() {
        let e = SessionError::NoSession {
            session_id: "s1".into(),
        };
        assert!(e.to_string().contains("s1"));

        let e = SessionError::MaxSessionsReached { limit: 42 };
        assert!(e.to_string().contains("42"));
    }

    // ── SessionManager: establish ───────────────────────────────────

    #[test]
    fn test_establish_session() {
        let mut mgr = default_manager();
        let result = mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1000,
            "t1".into(),
        );
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.session_id, "s1");
        assert_eq!(s.state, SessionState::Active);
    }

    #[test]
    fn test_establish_session_emits_event() {
        let mut mgr = default_manager();
        let _ = mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1000,
            "t1".into(),
        );
        let events = mgr.events();
        assert!(!events.is_empty());
        assert_eq!(events[0].event_code, event_codes::SCC_SESSION_ESTABLISHED);
    }

    #[test]
    fn test_max_sessions_enforced() {
        let config = SessionConfig {
            replay_window: 0,
            max_sessions: 2,
            session_timeout_ms: 60_000,
        };
        let mut mgr = SessionManager::new(config);
        mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "s".into(),
            1,
            "t".into(),
        )
        .unwrap();
        mgr.establish_session(
            "s2".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "s".into(),
            2,
            "t".into(),
        )
        .unwrap();
        let result = mgr.establish_session(
            "s3".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "s".into(),
            3,
            "t".into(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::MaxSessionsReached { limit } => assert_eq!(limit, 2),
            other => panic!("unexpected error: {other}"),
        }
    }

    // ── SessionManager: process message (strict mode) ───────────────

    #[test]
    fn test_strict_send_sequence() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let r0 = mgr.process_message("s1", MessageDirection::Send, 0, "h0", "sig0", 2000, "t");
        assert!(r0.is_ok());

        let r1 = mgr.process_message("s1", MessageDirection::Send, 1, "h1", "sig1", 3000, "t");
        assert!(r1.is_ok());

        // seq 1 again should fail (expected 2)
        let r_dup = mgr.process_message("s1", MessageDirection::Send, 1, "h1", "sig1", 4000, "t");
        assert!(r_dup.is_err());
    }

    #[test]
    fn test_strict_recv_sequence() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let r0 = mgr.process_message("s1", MessageDirection::Receive, 0, "h0", "sig0", 2000, "t");
        assert!(r0.is_ok());

        // Skip seq 1 — should fail
        let r2 = mgr.process_message("s1", MessageDirection::Receive, 2, "h2", "sig2", 3000, "t");
        assert!(r2.is_err());
    }

    #[test]
    fn test_independent_send_recv_sequences() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        // Send seq 0
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 0, "h", "s", 1, "t",)
                .is_ok()
        );

        // Recv seq 0 — independent counter
        assert!(
            mgr.process_message("s1", MessageDirection::Receive, 0, "h", "s", 2, "t",)
                .is_ok()
        );

        // Send seq 1
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 1, "h", "s", 3, "t",)
                .is_ok()
        );

        // Recv seq 1
        assert!(
            mgr.process_message("s1", MessageDirection::Receive, 1, "h", "s", 4, "t",)
                .is_ok()
        );
    }

    #[test]
    fn test_no_session_rejected() {
        let mut mgr = default_manager();
        let result =
            mgr.process_message("nonexistent", MessageDirection::Send, 0, "h", "s", 1, "t");
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::NoSession { session_id } => {
                assert_eq!(session_id, "nonexistent");
            }
            other => panic!("unexpected: {other}"),
        }
    }

    // ── SessionManager: terminated session ──────────────────────────

    #[test]
    fn test_terminated_session_rejects_messages() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        mgr.terminate_session("s1", 5000, "t").unwrap();

        let result = mgr.process_message("s1", MessageDirection::Send, 0, "h", "s", 6000, "t");
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::SessionTerminated { session_id } => {
                assert_eq!(session_id, "s1");
            }
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn test_terminate_emits_event() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        mgr.terminate_session("s1", 5000, "t").unwrap();

        let term_events: Vec<_> = mgr
            .events()
            .iter()
            .filter(|e| e.event_code == event_codes::SCC_SESSION_TERMINATED)
            .collect();
        assert_eq!(term_events.len(), 1);
    }

    #[test]
    fn test_terminate_nonexistent() {
        let mut mgr = default_manager();
        let result = mgr.terminate_session("nope", 5000, "t");
        assert!(result.is_err());
    }

    // ── SessionManager: windowed replay ─────────────────────────────

    #[test]
    fn test_windowed_out_of_order_accepted() {
        let config = SessionConfig {
            replay_window: 4,
            max_sessions: 10,
            session_timeout_ms: 60_000,
        };
        let mut mgr = SessionManager::new(config);
        establish_test_session(&mut mgr, "s1");

        // seq 0 ok
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 0, "h", "s", 1, "t",)
                .is_ok()
        );

        // seq 2 ok (skip 1)
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 2, "h", "s", 2, "t",)
                .is_ok()
        );

        // seq 1 ok (within window)
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 1, "h", "s", 3, "t",)
                .is_ok()
        );
    }

    #[test]
    fn test_windowed_replay_rejected() {
        let config = SessionConfig {
            replay_window: 4,
            max_sessions: 10,
            session_timeout_ms: 60_000,
        };
        let mut mgr = SessionManager::new(config);
        establish_test_session(&mut mgr, "s1");

        assert!(
            mgr.process_message("s1", MessageDirection::Send, 0, "h", "s", 1, "t",)
                .is_ok()
        );

        // Replay seq 0
        let result = mgr.process_message("s1", MessageDirection::Send, 0, "h", "s", 2, "t");
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::ReplayDetected { sequence, .. } => assert_eq!(sequence, 0),
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn test_windowed_regress_below_floor_rejected() {
        let config = SessionConfig {
            replay_window: 2,
            max_sessions: 10,
            session_timeout_ms: 60_000,
        };
        let mut mgr = SessionManager::new(config);
        establish_test_session(&mut mgr, "s1");

        // Advance to seq 5
        for seq in 0..6 {
            assert!(
                mgr.process_message("s1", MessageDirection::Send, seq, "h", "s", 100 + seq, "t",)
                    .is_ok()
            );
        }

        // Seq 2 should be rejected (below floor = 6)
        let result = mgr.process_message("s1", MessageDirection::Send, 2, "h", "s", 200, "t");
        assert!(result.is_err());
    }

    // ── SessionManager: key role validation ─────────────────────────

    #[test]
    fn test_validate_key_roles_ok() {
        let result = SessionManager::validate_key_roles(KeyRole::Encryption, KeyRole::Signing);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_key_roles_wrong_encryption() {
        let result = SessionManager::validate_key_roles(KeyRole::Signing, KeyRole::Signing);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::RoleMismatch { expected_role, .. } => {
                assert_eq!(expected_role, "Encryption");
            }
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn test_validate_key_roles_wrong_signing() {
        let result = SessionManager::validate_key_roles(KeyRole::Encryption, KeyRole::Issuance);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::RoleMismatch { expected_role, .. } => {
                assert_eq!(expected_role, "Signing");
            }
            other => panic!("unexpected: {other}"),
        }
    }

    // ── SessionManager: helpers ─────────────────────────────────────

    #[test]
    fn test_active_session_count() {
        let mut mgr = default_manager();
        assert_eq!(mgr.active_session_count(), 0);
        establish_test_session(&mut mgr, "s1");
        assert_eq!(mgr.active_session_count(), 1);
        establish_test_session(&mut mgr, "s2");
        assert_eq!(mgr.active_session_count(), 2);
        mgr.terminate_session("s1", 9999, "t").unwrap();
        assert_eq!(mgr.active_session_count(), 1);
    }

    #[test]
    fn test_get_session() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        assert!(mgr.get_session("s1").is_some());
        assert!(mgr.get_session("nonexistent").is_none());
    }

    #[test]
    fn test_session_ids() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        establish_test_session(&mut mgr, "s2");
        let ids = mgr.session_ids();
        assert!(ids.contains(&"s1".to_string()));
        assert!(ids.contains(&"s2".to_string()));
    }

    #[test]
    fn test_default_manager_fn() {
        let mgr = SessionManager::default_manager();
        assert_eq!(mgr.config().max_sessions, 256);
    }

    // ── Demo functions ──────────────────────────────────────────────

    #[test]
    fn test_demo_session_lifecycle() {
        let events = demo_session_lifecycle();
        // Should have: 1 establish + 3 send + 2 recv + 1 terminate = 7
        assert_eq!(events.len(), 7);
        assert_eq!(events[0].event_code, event_codes::SCC_SESSION_ESTABLISHED);
        assert_eq!(events[6].event_code, event_codes::SCC_SESSION_TERMINATED);
    }

    #[test]
    fn test_demo_windowed_replay() {
        let events = demo_windowed_replay();
        // 1 establish + 3 accepted + 1 rejected + 1 terminate = 6
        assert_eq!(events.len(), 6);
        let rejected: Vec<_> = events
            .iter()
            .filter(|e| e.event_code == event_codes::SCC_MESSAGE_REJECTED)
            .collect();
        assert_eq!(rejected.len(), 1);
    }

    // ── Multiple sessions ───────────────────────────────────────────

    #[test]
    fn test_multiple_sessions_independent() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        establish_test_session(&mut mgr, "s2");

        // Both can send seq 0 independently
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 0, "h", "s", 1, "t",)
                .is_ok()
        );
        assert!(
            mgr.process_message("s2", MessageDirection::Send, 0, "h", "s", 2, "t",)
                .is_ok()
        );

        // Terminating s1 doesn't affect s2
        mgr.terminate_session("s1", 100, "t").unwrap();
        assert!(
            mgr.process_message("s2", MessageDirection::Send, 1, "h", "s", 3, "t",)
                .is_ok()
        );
    }

    // ── AuthenticatedMessage fields ─────────────────────────────────

    #[test]
    fn test_message_fields() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let msg = mgr
            .process_message(
                "s1",
                MessageDirection::Send,
                0,
                "hash123",
                "sig456",
                1000,
                "t",
            )
            .unwrap();

        assert_eq!(msg.session_id, "s1");
        assert_eq!(msg.sequence, 0);
        assert_eq!(msg.payload_hash, "hash123");
        assert_eq!(msg.signature, "sig456");
    }

    // ── Event audit trail ───────────────────────────────────────────

    #[test]
    fn test_event_fields() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let event = &mgr.events()[0];
        assert_eq!(event.event_code, event_codes::SCC_SESSION_ESTABLISHED);
        assert_eq!(event.session_id, "s1");
        assert_eq!(event.trace_id, "trace-test");
        assert!(event.timestamp > 0);
    }

    #[test]
    fn test_rejection_event_on_sequence_violation() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        // Skip seq 0, try seq 5
        let _ = mgr.process_message("s1", MessageDirection::Send, 5, "h", "s", 1, "t");

        let reject_events: Vec<_> = mgr
            .events()
            .iter()
            .filter(|e| e.event_code == event_codes::SCC_MESSAGE_REJECTED)
            .collect();
        assert_eq!(reject_events.len(), 1);
    }

    // ── Serde roundtrip ─────────────────────────────────────────────

    #[test]
    fn test_session_state_serde() {
        let json = serde_json::to_string(&SessionState::Active).unwrap();
        let parsed: SessionState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SessionState::Active);
    }

    #[test]
    fn test_session_config_serde() {
        let cfg = SessionConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: SessionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.replay_window, cfg.replay_window);
        assert_eq!(parsed.max_sessions, cfg.max_sessions);
    }

    #[test]
    fn test_authenticated_session_serde() {
        let mut s = AuthenticatedSession::new(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "sg".into(),
            0,
        );
        s.activate(42);
        let json = serde_json::to_string(&s).unwrap();
        let parsed: AuthenticatedSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, "s1");
        assert_eq!(parsed.state, SessionState::Active);
    }

    #[test]
    fn test_message_direction_serde() {
        let json = serde_json::to_string(&MessageDirection::Send).unwrap();
        let parsed: MessageDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, MessageDirection::Send);
    }

    #[test]
    fn test_session_event_serde() {
        let e = SessionEvent {
            event_code: "SCC-001".to_string(),
            session_id: "s1".to_string(),
            trace_id: "t1".to_string(),
            detail: "test".to_string(),
            timestamp: 100,
        };
        let json = serde_json::to_string(&e).unwrap();
        let parsed: SessionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "SCC-001");
    }

    // ── Send + Sync ─────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<SessionState>();
        assert_sync::<SessionState>();
        assert_send::<AuthenticatedSession>();
        assert_sync::<AuthenticatedSession>();
        assert_send::<AuthenticatedMessage>();
        assert_sync::<AuthenticatedMessage>();
        assert_send::<SessionEvent>();
        assert_sync::<SessionEvent>();
        assert_send::<SessionConfig>();
        assert_sync::<SessionConfig>();
        assert_send::<SessionError>();
        assert_sync::<SessionError>();
    }
}
