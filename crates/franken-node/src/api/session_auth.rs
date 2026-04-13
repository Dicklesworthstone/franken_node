//! bd-oty / bd-ac8j: Session-authenticated control channel integration.
//!
//! Integrates the canonical ControlChannel (bd-v97o / bd-3cvu) and
//! KeyRoleRegistry (bd-364) into a unified session management layer
//! wrapping all control API endpoints.
//!
//! bd-ac8j replaces the placeholder authentication (record-only key IDs,
//! pass-through signatures) with real transcript-bound HMAC-SHA256
//! verification using epoch-scoped key derivation from the 10.13
//! control-channel verifier.
//!
//! # Invariants
//!
//! - INV-SCC-SESSION-AUTH: Every control message requires an active
//!   authenticated session with a verified transcript-bound MAC.
//! - INV-SCC-MONOTONIC: Per-direction sequence numbers are strictly monotonic.
//! - INV-SCC-ROLE-KEYS: Session uses Encryption key for exchange, Signing key
//!   for auth.
//! - INV-SCC-TERMINATED: Terminated sessions reject all further messages.
//! - INV-SCC-HANDSHAKE-BIND: Session ID is bound to the handshake transcript
//!   via HMAC — callers must prove possession of the root secret.
//! - INV-SCC-MSG-VERIFY: Message signatures are verified, not recorded.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};

use crate::connector::control_channel::Direction;
use crate::control_plane::control_epoch::ControlEpoch;
use crate::control_plane::key_role_separation::KeyRole;
use crate::security::constant_time::ct_eq_bytes;
use crate::security::epoch_scoped_keys::{RootSecret, SIGNATURE_LEN, derive_epoch_key};

type HmacSha256 = Hmac<Sha256>;

/// Domain separator for session-auth HMAC key derivation.
const SESSION_AUTH_DOMAIN: &str = "session_auth";

/// HMAC prefix for handshake transcript binding.
const HANDSHAKE_HMAC_PREFIX: &[u8] = b"session_auth_handshake_v1:";

/// HMAC prefix for per-message transcript binding.
const MESSAGE_HMAC_PREFIX: &[u8] = b"session_auth_message_v1:";

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
    /// Session expired due to inactivity timeout.
    pub const SCC_SESSION_EXPIRED: &str = "SCC-005";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Stable error codes for session-authenticated control channel.
pub mod error_codes {
    pub const ERR_SCC_NO_SESSION: &str = "ERR_SCC_NO_SESSION";
    pub const ERR_SCC_SEQUENCE_VIOLATION: &str = "ERR_SCC_SEQUENCE_VIOLATION";
    pub const ERR_SCC_SEQUENCE_EXHAUSTED: &str = "ERR_SCC_SEQUENCE_EXHAUSTED";
    pub const ERR_SCC_SESSION_TERMINATED: &str = "ERR_SCC_SESSION_TERMINATED";
    pub const ERR_SCC_SESSION_EXPIRED: &str = "ERR_SCC_SESSION_EXPIRED";
    pub const ERR_SCC_DUPLICATE_SESSION: &str = "ERR_SCC_DUPLICATE_SESSION";
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
    /// Session closed because the idle timeout elapsed.
    Expired,
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
            Self::Expired => "expired",
            Self::Terminated => "terminated",
        }
    }

    /// Whether the session can accept messages.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether the session still occupies live-session capacity.
    pub fn occupies_capacity(&self) -> bool {
        matches!(self, Self::Establishing | Self::Active | Self::Terminating)
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
    /// UTC timestamp (ms) of the last accepted activity on the session.
    pub last_activity_at: u64,
    /// Next outbound sequence number.
    pub send_seq: u64,
    /// True once the terminal outbound sequence has been consumed.
    #[serde(default)]
    pub send_seq_exhausted: bool,
    /// Next inbound sequence number.
    pub recv_seq: u64,
    /// True once the terminal inbound sequence has been consumed.
    #[serde(default)]
    pub recv_seq_exhausted: bool,
    /// Configured replay window size.
    pub replay_window: u64,
    /// Epoch under which this session was established.
    pub epoch: u64,
    /// HMAC binding the handshake transcript to the session ID.
    ///
    /// INV-SCC-HANDSHAKE-BIND: proves the session creator held the root
    /// secret at establishment time.
    #[serde(serialize_with = "serialize_mac", deserialize_with = "deserialize_mac")]
    pub handshake_mac: [u8; SIGNATURE_LEN],
}

fn serialize_mac<S: serde::Serializer>(mac: &[u8; SIGNATURE_LEN], s: S) -> Result<S::Ok, S::Error> {
    let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
    s.serialize_str(&hex)
}

fn deserialize_mac<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<[u8; SIGNATURE_LEN], D::Error> {
    let hex = String::deserialize(d)?;
    if hex.len() != SIGNATURE_LEN * 2 {
        return Err(serde::de::Error::custom(format!(
            "MAC hex string must be exactly {} chars, got {}",
            SIGNATURE_LEN * 2,
            hex.len()
        )));
    }
    let mut arr = [0u8; SIGNATURE_LEN];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or_else(|| {
            serde::de::Error::custom(format!("invalid hex char at position {}", i * 2))
        })?;
        let lo = hex_nibble(chunk[1]).ok_or_else(|| {
            serde::de::Error::custom(format!("invalid hex char at position {}", i * 2 + 1))
        })?;
        arr[i] = (hi << 4) | lo;
    }
    Ok(arr)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn allocate_next_sequence(
    counter: &mut u64,
    exhausted: &mut bool,
    session_id: &str,
    direction: MessageDirection,
) -> Result<u64, SessionError> {
    if *exhausted {
        return Err(SessionError::SequenceExhausted {
            session_id: session_id.to_string(),
            direction,
        });
    }

    let seq = *counter;
    if let Some(next) = counter.checked_add(1) {
        *counter = next;
    } else {
        *exhausted = true;
    }
    Ok(seq)
}

impl AuthenticatedSession {
    /// Create a new session in the Establishing state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: String,
        client_identity: String,
        server_identity: String,
        encryption_key_id: String,
        signing_key_id: String,
        replay_window: u64,
        epoch: u64,
        handshake_mac: [u8; SIGNATURE_LEN],
    ) -> Self {
        Self {
            session_id,
            state: SessionState::Establishing,
            client_identity,
            server_identity,
            encryption_key_id,
            signing_key_id,
            established_at: 0,
            last_activity_at: 0,
            send_seq: 0,
            send_seq_exhausted: false,
            recv_seq: 0,
            recv_seq_exhausted: false,
            replay_window,
            epoch,
            handshake_mac,
        }
    }

    /// Transition to Active state with the given timestamp.
    /// Only valid from Establishing state.
    pub fn activate(&mut self, timestamp: u64) {
        if self.state != SessionState::Establishing {
            return; // Guard: only Establishing → Active
        }
        self.state = SessionState::Active;
        self.established_at = timestamp;
        self.last_activity_at = timestamp;
    }

    /// Transition to Terminating state.
    /// Only valid from Active state.
    pub fn begin_termination(&mut self) {
        if self.state != SessionState::Active {
            return; // Guard: only Active → Terminating
        }
        self.state = SessionState::Terminating;
    }

    /// Transition to Terminated state.
    /// Only valid from Active, Terminating, or Expired state.
    pub fn terminate(&mut self) {
        if !matches!(
            self.state,
            SessionState::Active | SessionState::Terminating | SessionState::Expired
        ) {
            return; // Guard: only Active/Terminating/Expired → Terminated
        }
        self.state = SessionState::Terminated;
    }

    /// Transition to Expired state when idle timeout elapses.
    /// Terminating sessions stay non-reusable until explicit teardown.
    pub fn expire(&mut self) {
        if matches!(
            self.state,
            SessionState::Terminated | SessionState::Expired | SessionState::Terminating
        ) {
            return;
        }
        self.state = SessionState::Expired;
    }

    /// Record accepted activity for timeout enforcement.
    pub fn mark_activity(&mut self, timestamp: u64) {
        self.last_activity_at = timestamp;
    }

    /// Advance send sequence and return the assigned number.
    pub fn next_send_seq(&mut self) -> Result<u64, SessionError> {
        allocate_next_sequence(
            &mut self.send_seq,
            &mut self.send_seq_exhausted,
            &self.session_id,
            MessageDirection::Send,
        )
    }

    /// Advance recv sequence and return the assigned number.
    pub fn next_recv_seq(&mut self) -> Result<u64, SessionError> {
        allocate_next_sequence(
            &mut self.recv_seq,
            &mut self.recv_seq_exhausted,
            &self.session_id,
            MessageDirection::Receive,
        )
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
    /// Verified HMAC-SHA256 over the message transcript.
    ///
    /// INV-SCC-MSG-VERIFY: this field is only populated after the MAC
    /// has been verified against the session's root secret.
    #[serde(serialize_with = "serialize_mac", deserialize_with = "deserialize_mac")]
    pub verified_mac: [u8; SIGNATURE_LEN],
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

    /// Single-byte direction tag for transcript binding.
    fn tag(&self) -> u8 {
        match self {
            Self::Send => 0x01,
            Self::Receive => 0x02,
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
    /// Event code (SCC-001 through SCC-005).
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
    DuplicateLiveSession {
        session_id: String,
    },
    SequenceExhausted {
        session_id: String,
        direction: MessageDirection,
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
    SessionExpired {
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
            Self::DuplicateLiveSession { .. } => error_codes::ERR_SCC_DUPLICATE_SESSION,
            Self::SequenceExhausted { .. } => error_codes::ERR_SCC_SEQUENCE_EXHAUSTED,
            Self::SequenceViolation { .. } => error_codes::ERR_SCC_SEQUENCE_VIOLATION,
            Self::SessionTerminated { .. } => error_codes::ERR_SCC_SESSION_TERMINATED,
            Self::SessionExpired { .. } => error_codes::ERR_SCC_SESSION_EXPIRED,
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
            Self::DuplicateLiveSession { session_id } => {
                write!(f, "duplicate live session id: {session_id}")
            }
            Self::SequenceExhausted {
                session_id,
                direction,
            } => {
                write!(
                    f,
                    "sequence exhausted on {}: session={session_id}",
                    direction.label()
                )
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
            Self::SessionExpired { session_id } => {
                write!(f, "session expired: {session_id}")
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
use crate::capacity_defaults::aliases::MAX_SESSION_EVENTS;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
    }
    items.push(item);
}

// ---------------------------------------------------------------------------
// Transcript HMAC helpers
// ---------------------------------------------------------------------------

/// Build the handshake transcript preimage.
///
/// Binds: session_id, client_identity, server_identity, encryption_key_id,
/// signing_key_id, epoch, and timestamp into a length-prefixed preimage.
fn build_handshake_preimage(
    session_id: &str,
    client_identity: &str,
    server_identity: &str,
    encryption_key_id: &str,
    signing_key_id: &str,
    epoch: u64,
    timestamp: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    fn append_lp(buf: &mut Vec<u8>, field: &[u8]) {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field);
    }
    append_lp(&mut buf, session_id.as_bytes());
    append_lp(&mut buf, client_identity.as_bytes());
    append_lp(&mut buf, server_identity.as_bytes());
    append_lp(&mut buf, encryption_key_id.as_bytes());
    append_lp(&mut buf, signing_key_id.as_bytes());
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(&timestamp.to_le_bytes());
    buf
}

/// Compute the handshake transcript HMAC.
fn compute_handshake_mac(
    preimage: &[u8],
    epoch: ControlEpoch,
    root_secret: &RootSecret,
) -> [u8; SIGNATURE_LEN] {
    let derived_key = derive_epoch_key(root_secret, epoch, SESSION_AUTH_DOMAIN);
    let mut hmac =
        HmacSha256::new_from_slice(derived_key.as_bytes()).expect("HMAC key length is constant");
    hmac.update(HANDSHAKE_HMAC_PREFIX);
    hmac.update(preimage);
    let result = hmac.finalize().into_bytes();
    let mut mac = [0u8; SIGNATURE_LEN];
    mac.copy_from_slice(&result);
    mac
}

/// Build the per-message transcript preimage.
///
/// Binds: session_id, direction, sequence, payload_hash, epoch, and the
/// handshake_mac (chain binding) into a length-prefixed preimage.
fn build_message_preimage(
    session_id: &str,
    direction: MessageDirection,
    sequence: u64,
    payload_hash: &str,
    epoch: u64,
    handshake_mac: &[u8; SIGNATURE_LEN],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    fn append_lp(buf: &mut Vec<u8>, field: &[u8]) {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field);
    }
    append_lp(&mut buf, session_id.as_bytes());
    buf.push(direction.tag());
    buf.extend_from_slice(&sequence.to_le_bytes());
    append_lp(&mut buf, payload_hash.as_bytes());
    buf.extend_from_slice(&epoch.to_le_bytes());
    // Chain-bind to the handshake MAC (fixed-length, no length prefix needed).
    buf.extend_from_slice(handshake_mac);
    buf
}

/// Compute the per-message transcript HMAC.
fn compute_message_mac(
    preimage: &[u8],
    epoch: ControlEpoch,
    root_secret: &RootSecret,
) -> [u8; SIGNATURE_LEN] {
    let derived_key = derive_epoch_key(root_secret, epoch, SESSION_AUTH_DOMAIN);
    let mut hmac =
        HmacSha256::new_from_slice(derived_key.as_bytes()).expect("HMAC key length is constant");
    hmac.update(MESSAGE_HMAC_PREFIX);
    hmac.update(preimage);
    let result = hmac.finalize().into_bytes();
    let mut mac = [0u8; SIGNATURE_LEN];
    mac.copy_from_slice(&result);
    mac
}

/// Sign a session message and produce a MAC for verification.
///
/// Public API for callers to produce the correct MAC before calling
/// `process_message`. The caller must provide the session's handshake_mac
/// (obtained from `AuthenticatedSession::handshake_mac` after establishment).
#[allow(clippy::too_many_arguments)]
pub fn sign_session_message(
    session_id: &str,
    direction: MessageDirection,
    sequence: u64,
    payload_hash: &str,
    epoch: ControlEpoch,
    handshake_mac: &[u8; SIGNATURE_LEN],
    root_secret: &RootSecret,
) -> [u8; SIGNATURE_LEN] {
    let preimage = build_message_preimage(
        session_id,
        direction,
        sequence,
        payload_hash,
        epoch.value(),
        handshake_mac,
    );
    compute_message_mac(&preimage, epoch, root_secret)
}

/// Sign a session establishment handshake.
///
/// Public API for callers to produce the handshake MAC that must be
/// provided to `establish_session`.
#[allow(clippy::too_many_arguments)]
pub fn sign_handshake(
    session_id: &str,
    client_identity: &str,
    server_identity: &str,
    encryption_key_id: &str,
    signing_key_id: &str,
    epoch: ControlEpoch,
    timestamp: u64,
    root_secret: &RootSecret,
) -> [u8; SIGNATURE_LEN] {
    let preimage = build_handshake_preimage(
        session_id,
        client_identity,
        server_identity,
        encryption_key_id,
        signing_key_id,
        epoch.value(),
        timestamp,
    );
    compute_handshake_mac(&preimage, epoch, root_secret)
}

pub struct SessionManager {
    config: SessionConfig,
    /// Root secret for HMAC key derivation.
    root_secret: RootSecret,
    /// Current epoch for key scoping.
    epoch: ControlEpoch,
    sessions: BTreeMap<String, AuthenticatedSession>,
    /// Per-session, per-direction replay windows (for replay_window > 0).
    replay_windows: BTreeMap<(String, MessageDirection), BTreeSet<u64>>,
    events: Vec<SessionEvent>,
}

impl SessionManager {
    /// Create a new SessionManager with the given config, root secret, and epoch.
    pub fn new(config: SessionConfig, root_secret: RootSecret, epoch: ControlEpoch) -> Self {
        Self {
            config,
            root_secret,
            epoch,
            sessions: BTreeMap::new(),
            replay_windows: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    fn push_event(&mut self, event: SessionEvent) {
        push_bounded(&mut self.events, event, MAX_SESSION_EVENTS);
    }

    /// Current number of sessions that still occupy live-session capacity.
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.state.occupies_capacity())
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

    fn expire_stale_sessions(&mut self, timestamp: u64, trace_id: &str) {
        if self.config.session_timeout_ms == 0 {
            return;
        }

        let expired_session_ids: Vec<String> = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| {
                // Terminating sessions stay non-reusable until explicit teardown
                // completes; timing them out would reopen duplicate-id reuse.
                if matches!(
                    session.state,
                    SessionState::Expired | SessionState::Terminated | SessionState::Terminating
                ) {
                    return None;
                }
                let idle_for_ms = timestamp.saturating_sub(session.last_activity_at);
                (idle_for_ms >= self.config.session_timeout_ms).then(|| session_id.clone())
            })
            .collect();

        for session_id in expired_session_ids {
            if let Some(session) = self.sessions.get_mut(&session_id) {
                session.expire();
            }
            self.replay_windows.retain(|key, _| key.0 != session_id);
            self.push_event(SessionEvent {
                event_code: event_codes::SCC_SESSION_EXPIRED.to_string(),
                session_id: session_id.clone(),
                trace_id: trace_id.to_string(),
                detail: format!(
                    "session expired after {}ms inactivity",
                    self.config.session_timeout_ms
                ),
                timestamp,
            });
        }
    }

    /// Establish a new authenticated session.
    ///
    /// # INV-SCC-ROLE-KEYS
    /// Caller must supply the correct role-bound key IDs. The manager
    /// records them but the actual key-role verification is done at a
    /// higher layer (KeyRoleRegistry).
    ///
    /// # INV-SCC-HANDSHAKE-BIND
    /// The caller must provide a `handshake_mac` computed over the
    /// establishment transcript using `sign_handshake()`. The manager
    /// recomputes the HMAC and rejects the session if the MACs do not
    /// match, proving the caller holds the correct root secret.
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
        handshake_mac: [u8; SIGNATURE_LEN],
    ) -> Result<&AuthenticatedSession, SessionError> {
        self.expire_stale_sessions(timestamp, &trace_id);

        // INV-SCC-HANDSHAKE-BIND: verify handshake transcript MAC.
        let preimage = build_handshake_preimage(
            &session_id,
            &client_identity,
            &server_identity,
            &encryption_key_id,
            &signing_key_id,
            self.epoch.value(),
            timestamp,
        );
        let expected_mac = compute_handshake_mac(&preimage, self.epoch, &self.root_secret);

        if !ct_eq_bytes(&handshake_mac, &expected_mac) {
            self.push_event(SessionEvent {
                event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                session_id: session_id.clone(),
                trace_id,
                detail: "handshake MAC verification failed".to_string(),
                timestamp,
            });
            return Err(SessionError::AuthFailed {
                session_id,
                reason: "handshake MAC verification failed".into(),
            });
        }

        if self
            .sessions
            .get(&session_id)
            .is_some_and(|session| session.state.occupies_capacity())
        {
            self.push_event(SessionEvent {
                event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                session_id: session_id.clone(),
                trace_id,
                detail: "duplicate live session id".to_string(),
                timestamp,
            });
            return Err(SessionError::DuplicateLiveSession { session_id });
        }

        let active_sessions = self.active_session_count();
        if active_sessions >= self.config.max_sessions {
            self.push_event(SessionEvent {
                event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                session_id: session_id.clone(),
                trace_id,
                detail: format!(
                    "max sessions reached: active_sessions={active_sessions} limit={}",
                    self.config.max_sessions
                ),
                timestamp,
            });
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
            self.epoch.value(),
            handshake_mac,
        );
        session.activate(timestamp);

        self.replay_windows.retain(|key, _| key.0 != session_id);
        self.sessions.insert(session_id.clone(), session);

        self.push_event(SessionEvent {
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
    /// - Transcript-bound MAC verification (INV-SCC-MSG-VERIFY)
    /// - Sequence monotonicity (INV-SCC-MONOTONIC)
    /// - Replay detection for windowed mode
    #[allow(clippy::too_many_arguments)]
    pub fn process_message(
        &mut self,
        session_id: &str,
        direction: MessageDirection,
        sequence: u64,
        payload_hash: &str,
        message_mac: &[u8; SIGNATURE_LEN],
        timestamp: u64,
        trace_id: &str,
    ) -> Result<AuthenticatedMessage, SessionError> {
        self.expire_stale_sessions(timestamp, trace_id);

        // INV-SCC-SESSION-AUTH: session must exist
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| SessionError::NoSession {
                session_id: session_id.to_string(),
            })?;

        // INV-SCC-TERMINATED: terminated sessions reject all messages
        if session.state == SessionState::Terminated {
            self.push_event(SessionEvent {
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
            self.push_event(SessionEvent {
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

        if session.state == SessionState::Expired {
            self.push_event(SessionEvent {
                event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                session_id: session_id.to_string(),
                trace_id: trace_id.to_string(),
                detail: "session expired".to_string(),
                timestamp,
            });
            return Err(SessionError::SessionExpired {
                session_id: session_id.to_string(),
            });
        }

        if !session.state.is_active() {
            self.push_event(SessionEvent {
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

        // INV-SCC-MSG-VERIFY: verify transcript-bound MAC.
        // The MAC binds session_id, direction, sequence, payload_hash,
        // epoch, and the handshake_mac (chain binding).
        let handshake_mac = session.handshake_mac;
        let session_epoch = session.epoch;
        let preimage = build_message_preimage(
            session_id,
            direction,
            sequence,
            payload_hash,
            session_epoch,
            &handshake_mac,
        );
        let expected_mac = compute_message_mac(
            &preimage,
            ControlEpoch::from(session_epoch),
            &self.root_secret,
        );

        if !ct_eq_bytes(message_mac, &expected_mac) {
            self.push_event(SessionEvent {
                event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                session_id: session_id.to_string(),
                trace_id: trace_id.to_string(),
                detail: "message MAC verification failed".to_string(),
                timestamp,
            });
            return Err(SessionError::AuthFailed {
                session_id: session_id.to_string(),
                reason: "message MAC verification failed".into(),
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
                self.push_event(SessionEvent {
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
                self.push_event(SessionEvent {
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
                self.push_event(SessionEvent {
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
        let advance_result = {
            let session_mut =
                self.sessions
                    .get_mut(session_id)
                    .ok_or_else(|| SessionError::NoSession {
                        session_id: session_id.to_string(),
                    })?;

            match direction {
                MessageDirection::Send => {
                    if sequence >= session_mut.send_seq {
                        if session_mut.send_seq_exhausted {
                            Err(SessionError::SequenceExhausted {
                                session_id: session_id.to_string(),
                                direction,
                            })
                        } else {
                            if let Some(next) = sequence.checked_add(1) {
                                session_mut.send_seq = next;
                            } else {
                                session_mut.send_seq_exhausted = true;
                            }
                            Ok(())
                        }
                    } else {
                        Ok(())
                    }
                }
                MessageDirection::Receive => {
                    if sequence >= session_mut.recv_seq {
                        if session_mut.recv_seq_exhausted {
                            Err(SessionError::SequenceExhausted {
                                session_id: session_id.to_string(),
                                direction,
                            })
                        } else {
                            if let Some(next) = sequence.checked_add(1) {
                                session_mut.recv_seq = next;
                            } else {
                                session_mut.recv_seq_exhausted = true;
                            }
                            Ok(())
                        }
                    } else {
                        Ok(())
                    }
                }
            }
        };
        if let Err(err) = advance_result {
            self.push_event(SessionEvent {
                event_code: event_codes::SCC_MESSAGE_REJECTED.to_string(),
                session_id: session_id.to_string(),
                trace_id: trace_id.to_string(),
                detail: format!("sequence exhausted: dir={}", direction.label()),
                timestamp,
            });
            return Err(err);
        }

        self.sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NoSession {
                session_id: session_id.to_string(),
            })?
            .mark_activity(timestamp);

        let msg = AuthenticatedMessage {
            session_id: session_id.to_string(),
            sequence,
            direction,
            payload_hash: payload_hash.to_string(),
            verified_mac: *message_mac,
        };

        self.push_event(SessionEvent {
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

        self.push_event(SessionEvent {
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
    let root_secret = RootSecret::from_bytes([0xAA; 32]);
    let epoch = ControlEpoch::from(1u64);
    let mut mgr = SessionManager::new(config, root_secret.clone(), epoch);

    let handshake_mac = sign_handshake(
        "sess-001",
        "client-a",
        "server-1",
        "enc-key-001",
        "sign-key-001",
        epoch,
        1_000_000,
        &root_secret,
    );

    // Establish session
    let _ = mgr.establish_session(
        "sess-001".into(),
        "client-a".into(),
        "server-1".into(),
        "enc-key-001".into(),
        "sign-key-001".into(),
        1_000_000,
        "trace-001".into(),
        handshake_mac,
    );

    // Send 3 messages with strict monotonicity
    let session = mgr.get_session("sess-001").expect("should exist");
    let hmac_ref = session.handshake_mac;
    for seq in 0..3 {
        let ph = format!("hash-{seq}");
        let mac = sign_session_message(
            "sess-001",
            MessageDirection::Send,
            seq,
            &ph,
            epoch,
            &hmac_ref,
            &root_secret,
        );
        let _ = mgr.process_message(
            "sess-001",
            MessageDirection::Send,
            seq,
            &ph,
            &mac,
            1_000_000 + seq * 100,
            "trace-001",
        );
    }

    // Receive 2 messages
    for seq in 0..2 {
        let ph = format!("recv-hash-{seq}");
        let mac = sign_session_message(
            "sess-001",
            MessageDirection::Receive,
            seq,
            &ph,
            epoch,
            &hmac_ref,
            &root_secret,
        );
        let _ = mgr.process_message(
            "sess-001",
            MessageDirection::Receive,
            seq,
            &ph,
            &mac,
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
    let root_secret = RootSecret::from_bytes([0xBB; 32]);
    let epoch = ControlEpoch::from(1u64);
    let mut mgr = SessionManager::new(config, root_secret.clone(), epoch);

    let handshake_mac = sign_handshake(
        "sess-win",
        "client-b",
        "server-2",
        "enc-key-002",
        "sign-key-002",
        epoch,
        2_000_000,
        &root_secret,
    );

    let _ = mgr.establish_session(
        "sess-win".into(),
        "client-b".into(),
        "server-2".into(),
        "enc-key-002".into(),
        "sign-key-002".into(),
        2_000_000,
        "trace-002".into(),
        handshake_mac,
    );

    let hmac_ref = mgr
        .get_session("sess-win")
        .expect("should exist")
        .handshake_mac;

    // Send out-of-order within window
    let mac0 = sign_session_message(
        "sess-win",
        MessageDirection::Send,
        0,
        "hash-0",
        epoch,
        &hmac_ref,
        &root_secret,
    );
    let _ = mgr.process_message(
        "sess-win",
        MessageDirection::Send,
        0,
        "hash-0",
        &mac0,
        2_000_100,
        "trace-002",
    );

    let mac2 = sign_session_message(
        "sess-win",
        MessageDirection::Send,
        2,
        "hash-2",
        epoch,
        &hmac_ref,
        &root_secret,
    );
    let _ = mgr.process_message(
        "sess-win",
        MessageDirection::Send,
        2,
        "hash-2",
        &mac2,
        2_000_200,
        "trace-002",
    );

    let mac1 = sign_session_message(
        "sess-win",
        MessageDirection::Send,
        1,
        "hash-1",
        epoch,
        &hmac_ref,
        &root_secret,
    );
    let _ = mgr.process_message(
        "sess-win",
        MessageDirection::Send,
        1,
        "hash-1",
        &mac1,
        2_000_300,
        "trace-002",
    );

    // Attempt replay of seq 2 — should be rejected (same MAC, different payload)
    let mac2_dup = sign_session_message(
        "sess-win",
        MessageDirection::Send,
        2,
        "hash-2-dup",
        epoch,
        &hmac_ref,
        &root_secret,
    );
    let _ = mgr.process_message(
        "sess-win",
        MessageDirection::Send,
        2,
        "hash-2-dup",
        &mac2_dup,
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

    const TEST_SECRET: [u8; 32] = [0xAA; 32];

    fn test_root_secret() -> RootSecret {
        RootSecret::from_bytes(TEST_SECRET)
    }

    fn test_epoch() -> ControlEpoch {
        ControlEpoch::from(1u64)
    }

    fn default_manager() -> SessionManager {
        SessionManager::new(
            SessionConfig {
                replay_window: 0,
                max_sessions: 10,
                session_timeout_ms: 60_000,
            },
            test_root_secret(),
            test_epoch(),
        )
    }

    fn establish_test_session(mgr: &mut SessionManager, sid: &str) {
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mac = sign_handshake(
            sid, "client-a", "server-1", "enc-key", "sign-key", epoch, 1_000_000, &rs,
        );
        mgr.establish_session(
            sid.to_string(),
            "client-a".into(),
            "server-1".into(),
            "enc-key".into(),
            "sign-key".into(),
            1_000_000,
            "trace-test".into(),
            mac,
        )
        .unwrap();
    }

    /// Sign a message for a test session (retrieves handshake_mac from the session).
    fn sign_msg(
        mgr: &SessionManager,
        sid: &str,
        dir: MessageDirection,
        seq: u64,
        payload_hash: &str,
    ) -> [u8; SIGNATURE_LEN] {
        let session = mgr.get_session(sid).expect("should exist");
        sign_session_message(
            sid,
            dir,
            seq,
            payload_hash,
            test_epoch(),
            &session.handshake_mac,
            &test_root_secret(),
        )
    }

    // ── SessionState tests ──────────────────────────────────────────

    #[test]
    fn test_session_state_labels() {
        assert_eq!(SessionState::Establishing.label(), "establishing");
        assert_eq!(SessionState::Active.label(), "active");
        assert_eq!(SessionState::Terminating.label(), "terminating");
        assert_eq!(SessionState::Expired.label(), "expired");
        assert_eq!(SessionState::Terminated.label(), "terminated");
    }

    #[test]
    fn test_session_state_is_active() {
        assert!(!SessionState::Establishing.is_active());
        assert!(SessionState::Active.is_active());
        assert!(!SessionState::Terminating.is_active());
        assert!(!SessionState::Expired.is_active());
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
            1,
            [0u8; SIGNATURE_LEN],
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
            1,
            [0u8; SIGNATURE_LEN],
        );
        s.activate(42);
        assert_eq!(s.state, SessionState::Active);
        assert_eq!(s.established_at, 42);
        assert_eq!(s.last_activity_at, 42);
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
            1,
            [0u8; SIGNATURE_LEN],
        );
        s.activate(1);
        assert_eq!(s.state, SessionState::Active);
        s.begin_termination();
        assert_eq!(s.state, SessionState::Terminating);
        s.expire();
        assert_eq!(s.state, SessionState::Terminating);
        s.terminate();
        assert_eq!(s.state, SessionState::Terminated);
    }

    #[test]
    fn test_terminating_session_does_not_expire() {
        let mut s = AuthenticatedSession::new(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "sg".into(),
            0,
            1,
            [0u8; SIGNATURE_LEN],
        );
        s.activate(1);
        s.begin_termination();
        s.expire();
        assert_eq!(s.state, SessionState::Terminating);
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
            1,
            [0u8; SIGNATURE_LEN],
        );
        assert_eq!(s.next_send_seq().unwrap(), 0);
        assert_eq!(s.next_send_seq().unwrap(), 1);
        assert_eq!(s.next_send_seq().unwrap(), 2);
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
            1,
            [0u8; SIGNATURE_LEN],
        );
        assert_eq!(s.next_recv_seq().unwrap(), 0);
        assert_eq!(s.next_recv_seq().unwrap(), 1);
    }

    #[test]
    fn test_next_send_seq_fails_closed_at_terminal_boundary() {
        let mut s = AuthenticatedSession::new(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "sg".into(),
            0,
            1,
            [0u8; SIGNATURE_LEN],
        );
        s.send_seq = u64::MAX - 1;

        assert_eq!(s.next_send_seq().unwrap(), u64::MAX - 1);
        assert_eq!(s.next_send_seq().unwrap(), u64::MAX);
        match s
            .next_send_seq()
            .expect_err("terminal send sequence must fail closed")
        {
            SessionError::SequenceExhausted {
                session_id,
                direction,
            } => {
                assert_eq!(session_id, "s1");
                assert_eq!(direction, MessageDirection::Send);
            }
            other => unreachable!("unexpected error: {other}"),
        }
        assert!(s.send_seq_exhausted);
    }

    #[test]
    fn test_next_recv_seq_fails_closed_at_terminal_boundary() {
        let mut s = AuthenticatedSession::new(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "sg".into(),
            0,
            1,
            [0u8; SIGNATURE_LEN],
        );
        s.recv_seq = u64::MAX - 1;

        assert_eq!(s.next_recv_seq().unwrap(), u64::MAX - 1);
        assert_eq!(s.next_recv_seq().unwrap(), u64::MAX);
        match s
            .next_recv_seq()
            .expect_err("terminal recv sequence must fail closed")
        {
            SessionError::SequenceExhausted {
                session_id,
                direction,
            } => {
                assert_eq!(session_id, "s1");
                assert_eq!(direction, MessageDirection::Receive);
            }
            other => unreachable!("unexpected error: {other}"),
        }
        assert!(s.recv_seq_exhausted);
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

        let e2 = SessionError::DuplicateLiveSession {
            session_id: "s".into(),
        };
        assert_eq!(e2.code(), "ERR_SCC_DUPLICATE_SESSION");

        let e3 = SessionError::SequenceViolation {
            session_id: "s".into(),
            direction: MessageDirection::Send,
            expected_min: 5,
            got: 3,
        };
        assert_eq!(e3.code(), "ERR_SCC_SEQUENCE_VIOLATION");

        let exhausted = SessionError::SequenceExhausted {
            session_id: "s".into(),
            direction: MessageDirection::Receive,
        };
        assert_eq!(exhausted.code(), "ERR_SCC_SEQUENCE_EXHAUSTED");

        let e4 = SessionError::SessionTerminated {
            session_id: "s".into(),
        };
        assert_eq!(e4.code(), "ERR_SCC_SESSION_TERMINATED");

        let e5 = SessionError::SessionExpired {
            session_id: "s".into(),
        };
        assert_eq!(e5.code(), "ERR_SCC_SESSION_EXPIRED");

        let e6 = SessionError::RoleMismatch {
            session_id: "s".into(),
            expected_role: "Signing".into(),
            actual_role: "Encryption".into(),
        };
        assert_eq!(e6.code(), "ERR_SCC_ROLE_MISMATCH");

        let e7 = SessionError::AuthFailed {
            session_id: "s".into(),
            reason: "bad sig".into(),
        };
        assert_eq!(e7.code(), "ERR_SCC_AUTH_FAILED");

        let e8 = SessionError::MaxSessionsReached { limit: 10 };
        assert_eq!(e8.code(), "ERR_SCC_MAX_SESSIONS");
    }

    #[test]
    fn test_error_display() {
        let e = SessionError::NoSession {
            session_id: "s1".into(),
        };
        assert!(e.to_string().contains("s1"));
        let e = SessionError::DuplicateLiveSession {
            session_id: "dup".into(),
        };
        assert!(e.to_string().contains("dup"));
        let e = SessionError::SequenceExhausted {
            session_id: "exhausted".into(),
            direction: MessageDirection::Send,
        };
        assert!(e.to_string().contains("exhausted"));
        let e = SessionError::SessionExpired {
            session_id: "expired".into(),
        };
        assert!(e.to_string().contains("expired"));
        let e = SessionError::MaxSessionsReached { limit: 42 };
        assert!(e.to_string().contains("42"));
    }

    // ── SessionManager: establish ───────────────────────────────────

    #[test]
    fn test_establish_session() {
        let mut mgr = default_manager();
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mac = sign_handshake("s1", "c", "sv", "ek", "sk", epoch, 1000, &rs);
        let result = mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1000,
            "t1".into(),
            mac,
        );
        assert!(result.is_ok());
        let s = result.expect("should succeed");
        assert_eq!(s.session_id, "s1");
        assert_eq!(s.state, SessionState::Active);
    }

    #[test]
    fn test_establish_session_emits_event() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
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
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mut mgr = SessionManager::new(config, rs.clone(), epoch);

        for (i, sid) in ["s1", "s2"].iter().enumerate() {
            let mac = sign_handshake(sid, "c", "sv", "e", "s", epoch, i as u64, &rs);
            mgr.establish_session(
                sid.to_string(),
                "c".into(),
                "sv".into(),
                "e".into(),
                "s".into(),
                i as u64,
                "t".into(),
                mac,
            )
            .unwrap();
        }

        let mac3 = sign_handshake("s3", "c", "sv", "e", "s", epoch, 3, &rs);
        let result = mgr.establish_session(
            "s3".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "s".into(),
            3,
            "t".into(),
            mac3,
        );
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::MaxSessionsReached { limit } => assert_eq!(limit, 2),
            other => unreachable!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_expired_sessions_release_capacity_for_new_session() {
        let config = SessionConfig {
            replay_window: 0,
            max_sessions: 1,
            session_timeout_ms: 10,
        };
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mut mgr = SessionManager::new(config, rs.clone(), epoch);

        let mac1 = sign_handshake("s1", "c", "sv", "e", "s", epoch, 1_000, &rs);
        mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "s".into(),
            1_000,
            "t".into(),
            mac1,
        )
        .unwrap();

        let mac2 = sign_handshake("s2", "c", "sv", "e", "s", epoch, 1_011, &rs);
        let established = mgr.establish_session(
            "s2".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "s".into(),
            1_011,
            "t".into(),
            mac2,
        );
        assert!(established.is_ok());
        assert_eq!(mgr.active_session_count(), 1);
        assert_eq!(mgr.get_session("s1").unwrap().state, SessionState::Expired);
    }

    #[test]
    fn test_duplicate_live_session_id_rejected_without_resetting_counters() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let mac0 = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h0");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 0, "h0", &mac0, 2_000, "t")
                .is_ok()
        );

        let rs = test_root_secret();
        let epoch = test_epoch();
        let duplicate_mac = sign_handshake(
            "s1", "client-a", "server-1", "enc-key", "sign-key", epoch, 3_000, &rs,
        );
        let duplicate = mgr.establish_session(
            "s1".into(),
            "client-a".into(),
            "server-1".into(),
            "enc-key".into(),
            "sign-key".into(),
            3_000,
            "trace-dup".into(),
            duplicate_mac,
        );
        match duplicate.expect_err("duplicate live session id must fail") {
            SessionError::DuplicateLiveSession { session_id } => assert_eq!(session_id, "s1"),
            other => unreachable!("unexpected error: {other}"),
        }

        assert_eq!(mgr.get_session("s1").unwrap().send_seq, 1);

        let mac1 = sign_msg(&mgr, "s1", MessageDirection::Send, 1, "h1");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 1, "h1", &mac1, 4_000, "t")
                .is_ok()
        );

        let stale_mac0 = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h0");
        assert!(
            mgr.process_message(
                "s1",
                MessageDirection::Send,
                0,
                "h0",
                &stale_mac0,
                5_000,
                "t"
            )
            .is_err()
        );
    }

    #[test]
    fn test_duplicate_establishing_session_id_rejected() {
        let mut mgr = default_manager();
        let rs = test_root_secret();
        let epoch = test_epoch();

        let handshake_mac = sign_handshake(
            "s1", "client-a", "server-1", "enc-key", "sign-key", epoch, 2_000, &rs,
        );
        let mut establishing = AuthenticatedSession::new(
            "s1".into(),
            "client-a".into(),
            "server-1".into(),
            "enc-key".into(),
            "sign-key".into(),
            mgr.config().replay_window,
            epoch.value(),
            handshake_mac,
        );
        establishing.last_activity_at = 2_000;
        mgr.sessions.insert("s1".into(), establishing);

        assert_eq!(mgr.active_session_count(), 1);

        let duplicate_mac = sign_handshake(
            "s1", "client-a", "server-1", "enc-key", "sign-key", epoch, 3_000, &rs,
        );
        let duplicate = mgr.establish_session(
            "s1".into(),
            "client-a".into(),
            "server-1".into(),
            "enc-key".into(),
            "sign-key".into(),
            3_000,
            "trace-dup-establishing".into(),
            duplicate_mac,
        );
        match duplicate.expect_err("establishing session id must stay reserved") {
            SessionError::DuplicateLiveSession { session_id } => assert_eq!(session_id, "s1"),
            other => unreachable!("unexpected error: {other}"),
        }

        let preserved = mgr
            .get_session("s1")
            .expect("establishing session preserved after rejection");
        assert_eq!(preserved.state, SessionState::Establishing);
        assert_eq!(preserved.established_at, 0);
        assert_eq!(preserved.last_activity_at, 2_000);
        assert_eq!(preserved.send_seq, 0);
        assert_eq!(preserved.recv_seq, 0);
        assert_eq!(mgr.active_session_count(), 1);

        let rejection = mgr
            .events()
            .last()
            .expect("duplicate establishing rejection event recorded");
        assert_eq!(rejection.event_code, event_codes::SCC_MESSAGE_REJECTED);
        assert_eq!(rejection.session_id, "s1");
        assert_eq!(rejection.trace_id, "trace-dup-establishing");
        assert_eq!(rejection.detail, "duplicate live session id");
        assert_eq!(rejection.timestamp, 3_000);
    }

    #[test]
    fn test_duplicate_terminating_session_id_rejected() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        mgr.sessions
            .get_mut("s1")
            .expect("session exists")
            .begin_termination();

        let rs = test_root_secret();
        let epoch = test_epoch();
        let duplicate_mac = sign_handshake(
            "s1", "client-a", "server-1", "enc-key", "sign-key", epoch, 3_000, &rs,
        );
        let duplicate = mgr.establish_session(
            "s1".into(),
            "client-a".into(),
            "server-1".into(),
            "enc-key".into(),
            "sign-key".into(),
            3_000,
            "trace-dup-term".into(),
            duplicate_mac,
        );
        assert!(matches!(
            duplicate,
            Err(SessionError::DuplicateLiveSession { .. })
        ));
    }

    #[test]
    fn test_timed_out_terminating_session_id_still_rejected_without_resetting_counters() {
        let config = SessionConfig {
            replay_window: 0,
            max_sessions: 10,
            session_timeout_ms: 10,
        };
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mut mgr = SessionManager::new(config, rs.clone(), epoch);

        let initial_mac = sign_handshake("s1", "c", "sv", "ek", "sk", epoch, 1_000, &rs);
        mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1_000,
            "trace-initial".into(),
            initial_mac,
        )
        .expect("initial session");

        let message_mac = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h0");
        mgr.process_message(
            "s1",
            MessageDirection::Send,
            0,
            "h0",
            &message_mac,
            1_005,
            "t",
        )
        .expect("message accepted");

        mgr.sessions
            .get_mut("s1")
            .expect("session exists")
            .begin_termination();

        let duplicate_mac = sign_handshake("s1", "c", "sv", "ek", "sk", epoch, 1_020, &rs);
        let duplicate = mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1_020,
            "trace-dup-term-timeout".into(),
            duplicate_mac,
        );

        match duplicate.expect_err("timed-out terminating session must still block duplicate id") {
            SessionError::DuplicateLiveSession { session_id } => assert_eq!(session_id, "s1"),
            other => unreachable!("unexpected error: {other}"),
        }

        let original = mgr.get_session("s1").expect("original session preserved");
        assert_eq!(original.state, SessionState::Terminating);
        assert_eq!(original.send_seq, 1);
    }

    #[test]
    fn test_terminating_session_still_counts_toward_max_sessions() {
        let config = SessionConfig {
            replay_window: 0,
            max_sessions: 1,
            session_timeout_ms: 60_000,
        };
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mut mgr = SessionManager::new(config, rs.clone(), epoch);

        let initial_mac = sign_handshake("s1", "c", "sv", "ek", "sk", epoch, 1_000, &rs);
        mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1_000,
            "trace-initial".into(),
            initial_mac,
        )
        .expect("initial session");

        mgr.sessions
            .get_mut("s1")
            .expect("session exists")
            .begin_termination();

        let second_mac = sign_handshake("s2", "c", "sv", "ek", "sk", epoch, 2_000, &rs);
        let second = mgr.establish_session(
            "s2".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            2_000,
            "trace-second".into(),
            second_mac,
        );

        match second.expect_err("terminating session must still consume capacity") {
            SessionError::MaxSessionsReached { limit } => assert_eq!(limit, 1),
            other => unreachable!("unexpected error: {other}"),
        }

        assert!(mgr.get_session("s2").is_none());
        assert_eq!(mgr.active_session_count(), 1);
        assert_eq!(
            mgr.get_session("s1").unwrap().state,
            SessionState::Terminating
        );
        let rejection = mgr.events().last().expect("capacity rejection event");
        assert_eq!(rejection.event_code, event_codes::SCC_MESSAGE_REJECTED);
        assert_eq!(rejection.session_id, "s2");
        assert_eq!(rejection.trace_id, "trace-second");
        assert_eq!(rejection.timestamp, 2_000);
        assert_eq!(
            rejection.detail,
            "max sessions reached: active_sessions=1 limit=1"
        );
    }

    #[test]
    fn test_reestablish_same_session_id_after_termination_allowed() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        mgr.terminate_session("s1", 2_000, "trace-term")
            .expect("termination succeeds");

        let rs = test_root_secret();
        let epoch = test_epoch();
        let reestablish_mac = sign_handshake(
            "s1", "client-a", "server-1", "enc-key", "sign-key", epoch, 3_000, &rs,
        );
        let reestablished = mgr.establish_session(
            "s1".into(),
            "client-a".into(),
            "server-1".into(),
            "enc-key".into(),
            "sign-key".into(),
            3_000,
            "trace-reestablish-term".into(),
            reestablish_mac,
        );
        assert!(reestablished.is_ok());
        assert_eq!(mgr.get_session("s1").unwrap().send_seq, 0);
    }

    #[test]
    fn test_reestablish_same_session_id_after_expiration_allowed() {
        let config = SessionConfig {
            replay_window: 0,
            max_sessions: 10,
            session_timeout_ms: 10,
        };
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mut mgr = SessionManager::new(config, rs.clone(), epoch);

        let mac = sign_handshake("s1", "c", "sv", "ek", "sk", epoch, 1_000, &rs);
        mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1_000,
            "trace-initial".into(),
            mac,
        )
        .unwrap();

        let reestablish_mac = sign_handshake("s1", "c", "sv", "ek", "sk", epoch, 1_011, &rs);
        let reestablished = mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1_011,
            "trace-expired".into(),
            reestablish_mac,
        );
        assert!(reestablished.is_ok());
        assert_eq!(mgr.get_session("s1").unwrap().state, SessionState::Active);
        assert_eq!(mgr.get_session("s1").unwrap().established_at, 1_011);
    }

    // ── SessionManager: process message (strict mode) ───────────────

    #[test]
    fn test_strict_send_sequence() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let mac0 = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h0");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 0, "h0", &mac0, 2000, "t")
                .is_ok()
        );

        let mac1 = sign_msg(&mgr, "s1", MessageDirection::Send, 1, "h1");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 1, "h1", &mac1, 3000, "t")
                .is_ok()
        );

        // seq 1 again should fail (expected 2) — even with valid MAC for seq 1
        let mac1_dup = sign_msg(&mgr, "s1", MessageDirection::Send, 1, "h1");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 1, "h1", &mac1_dup, 4000, "t")
                .is_err()
        );
    }

    #[test]
    fn test_strict_recv_sequence() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let mac0 = sign_msg(&mgr, "s1", MessageDirection::Receive, 0, "h0");
        assert!(
            mgr.process_message("s1", MessageDirection::Receive, 0, "h0", &mac0, 2000, "t")
                .is_ok()
        );

        // Skip seq 1 — should fail
        let mac2 = sign_msg(&mgr, "s1", MessageDirection::Receive, 2, "h2");
        assert!(
            mgr.process_message("s1", MessageDirection::Receive, 2, "h2", &mac2, 3000, "t")
                .is_err()
        );
    }

    #[test]
    fn test_independent_send_recv_sequences() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let mac_s0 = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 0, "h", &mac_s0, 1, "t")
                .is_ok()
        );

        let mac_r0 = sign_msg(&mgr, "s1", MessageDirection::Receive, 0, "h");
        assert!(
            mgr.process_message("s1", MessageDirection::Receive, 0, "h", &mac_r0, 2, "t")
                .is_ok()
        );

        let mac_s1 = sign_msg(&mgr, "s1", MessageDirection::Send, 1, "h");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 1, "h", &mac_s1, 3, "t")
                .is_ok()
        );

        let mac_r1 = sign_msg(&mgr, "s1", MessageDirection::Receive, 1, "h");
        assert!(
            mgr.process_message("s1", MessageDirection::Receive, 1, "h", &mac_r1, 4, "t")
                .is_ok()
        );
    }

    #[test]
    fn test_send_sequence_exhaustion_rejected_before_duplicate_terminal_use() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        mgr.sessions.get_mut("s1").unwrap().send_seq = u64::MAX - 1;

        let final_mac = sign_msg(&mgr, "s1", MessageDirection::Send, u64::MAX - 1, "h-final");
        assert!(
            mgr.process_message(
                "s1",
                MessageDirection::Send,
                u64::MAX - 1,
                "h-final",
                &final_mac,
                2_000,
                "t"
            )
            .is_ok()
        );
        assert_eq!(mgr.get_session("s1").unwrap().send_seq, u64::MAX);
        assert!(!mgr.get_session("s1").unwrap().send_seq_exhausted);

        let terminal_mac = sign_msg(&mgr, "s1", MessageDirection::Send, u64::MAX, "h-terminal");
        assert!(
            mgr.process_message(
                "s1",
                MessageDirection::Send,
                u64::MAX,
                "h-terminal",
                &terminal_mac,
                3_000,
                "t",
            )
            .is_ok()
        );
        assert_eq!(mgr.get_session("s1").unwrap().send_seq, u64::MAX);
        assert!(mgr.get_session("s1").unwrap().send_seq_exhausted);

        let exhausted_mac = sign_msg(&mgr, "s1", MessageDirection::Send, u64::MAX, "h-overflow");
        match mgr
            .process_message(
                "s1",
                MessageDirection::Send,
                u64::MAX,
                "h-overflow",
                &exhausted_mac,
                4_000,
                "t",
            )
            .expect_err("terminal send sequence must fail closed")
        {
            SessionError::SequenceExhausted {
                session_id,
                direction,
            } => {
                assert_eq!(session_id, "s1");
                assert_eq!(direction, MessageDirection::Send);
            }
            other => unreachable!("unexpected error: {other}"),
        }
        let rejection = mgr
            .events()
            .last()
            .expect("send exhaustion rejection event");
        assert_eq!(rejection.event_code, event_codes::SCC_MESSAGE_REJECTED);
        assert!(rejection.detail.contains("sequence exhausted"));
    }

    #[test]
    fn test_recv_sequence_exhaustion_rejected_before_duplicate_terminal_use() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        mgr.sessions.get_mut("s1").unwrap().recv_seq = u64::MAX - 1;

        let final_mac = sign_msg(
            &mgr,
            "s1",
            MessageDirection::Receive,
            u64::MAX - 1,
            "h-final",
        );
        assert!(
            mgr.process_message(
                "s1",
                MessageDirection::Receive,
                u64::MAX - 1,
                "h-final",
                &final_mac,
                2_000,
                "t"
            )
            .is_ok()
        );
        assert_eq!(mgr.get_session("s1").unwrap().recv_seq, u64::MAX);
        assert!(!mgr.get_session("s1").unwrap().recv_seq_exhausted);

        let terminal_mac = sign_msg(
            &mgr,
            "s1",
            MessageDirection::Receive,
            u64::MAX,
            "h-terminal",
        );
        assert!(
            mgr.process_message(
                "s1",
                MessageDirection::Receive,
                u64::MAX,
                "h-terminal",
                &terminal_mac,
                3_000,
                "t",
            )
            .is_ok()
        );
        assert_eq!(mgr.get_session("s1").unwrap().recv_seq, u64::MAX);
        assert!(mgr.get_session("s1").unwrap().recv_seq_exhausted);

        let exhausted_mac = sign_msg(
            &mgr,
            "s1",
            MessageDirection::Receive,
            u64::MAX,
            "h-overflow",
        );
        match mgr
            .process_message(
                "s1",
                MessageDirection::Receive,
                u64::MAX,
                "h-overflow",
                &exhausted_mac,
                4_000,
                "t",
            )
            .expect_err("terminal recv sequence must fail closed")
        {
            SessionError::SequenceExhausted {
                session_id,
                direction,
            } => {
                assert_eq!(session_id, "s1");
                assert_eq!(direction, MessageDirection::Receive);
            }
            other => unreachable!("unexpected error: {other}"),
        }
        let rejection = mgr
            .events()
            .last()
            .expect("recv exhaustion rejection event");
        assert_eq!(rejection.event_code, event_codes::SCC_MESSAGE_REJECTED);
        assert!(rejection.detail.contains("sequence exhausted"));
    }

    #[test]
    fn test_no_session_rejected() {
        let mut mgr = default_manager();
        let fake_mac = [0u8; SIGNATURE_LEN];
        let result = mgr.process_message(
            "nonexistent",
            MessageDirection::Send,
            0,
            "h",
            &fake_mac,
            1,
            "t",
        );
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::NoSession { session_id } => assert_eq!(session_id, "nonexistent"),
            other => unreachable!("unexpected: {other}"),
        }
    }

    // ── SessionManager: terminated session ──────────────────────────

    #[test]
    fn test_terminated_session_rejects_messages() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        let mac = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h");
        mgr.terminate_session("s1", 5000, "t")
            .expect("should succeed");

        let result = mgr.process_message("s1", MessageDirection::Send, 0, "h", &mac, 6000, "t");
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::SessionTerminated { session_id } => assert_eq!(session_id, "s1"),
            other => unreachable!("unexpected: {other}"),
        }
    }

    #[test]
    fn test_expired_session_rejects_messages() {
        let config = SessionConfig {
            replay_window: 0,
            max_sessions: 10,
            session_timeout_ms: 10,
        };
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mut mgr = SessionManager::new(config, rs.clone(), epoch);
        let mac = sign_handshake("s1", "c", "sv", "ek", "sk", epoch, 1_000, &rs);
        mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1_000,
            "trace-test".into(),
            mac,
        )
        .unwrap();

        let msg_mac = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h");
        let result = mgr.process_message(
            "s1",
            MessageDirection::Send,
            0,
            "h",
            &msg_mac,
            1_011,
            "trace-expired",
        );
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::SessionExpired { session_id } => assert_eq!(session_id, "s1"),
            other => unreachable!("unexpected: {other}"),
        }

        let expiry_events: Vec<_> = mgr
            .events()
            .iter()
            .filter(|event| event.event_code == event_codes::SCC_SESSION_EXPIRED)
            .collect();
        assert_eq!(expiry_events.len(), 1);
    }

    #[test]
    fn test_terminate_emits_event() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        mgr.terminate_session("s1", 5000, "t")
            .expect("should succeed");

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
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mut mgr = SessionManager::new(config, rs.clone(), epoch);
        establish_test_session(&mut mgr, "s1");

        let mac0 = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 0, "h", &mac0, 1, "t")
                .is_ok()
        );

        let mac2 = sign_msg(&mgr, "s1", MessageDirection::Send, 2, "h");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 2, "h", &mac2, 2, "t")
                .is_ok()
        );

        let mac1 = sign_msg(&mgr, "s1", MessageDirection::Send, 1, "h");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 1, "h", &mac1, 3, "t")
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
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mut mgr = SessionManager::new(config, rs.clone(), epoch);
        establish_test_session(&mut mgr, "s1");

        let mac0 = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 0, "h", &mac0, 1, "t")
                .is_ok()
        );

        // Replay seq 0
        let mac0_dup = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h");
        let result = mgr.process_message("s1", MessageDirection::Send, 0, "h", &mac0_dup, 2, "t");
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::ReplayDetected { sequence, .. } => assert_eq!(sequence, 0),
            other => unreachable!("unexpected: {other}"),
        }
    }

    #[test]
    fn test_windowed_regress_below_floor_rejected() {
        let config = SessionConfig {
            replay_window: 2,
            max_sessions: 10,
            session_timeout_ms: 60_000,
        };
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mut mgr = SessionManager::new(config, rs.clone(), epoch);
        establish_test_session(&mut mgr, "s1");

        for seq in 0..6 {
            let ph = format!("h{seq}");
            let mac = sign_msg(&mgr, "s1", MessageDirection::Send, seq, &ph);
            assert!(
                mgr.process_message("s1", MessageDirection::Send, seq, &ph, &mac, 100 + seq, "t")
                    .is_ok()
            );
        }

        // Seq 2 should be rejected (below floor)
        let mac_old = sign_msg(&mgr, "s1", MessageDirection::Send, 2, "h2");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 2, "h2", &mac_old, 200, "t")
                .is_err()
        );
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
        match result.expect_err("should fail") {
            SessionError::RoleMismatch { expected_role, .. } => {
                assert_eq!(expected_role, "Encryption")
            }
            other => unreachable!("unexpected: {other}"),
        }
    }

    #[test]
    fn test_validate_key_roles_wrong_signing() {
        let result = SessionManager::validate_key_roles(KeyRole::Encryption, KeyRole::Issuance);
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::RoleMismatch { expected_role, .. } => {
                assert_eq!(expected_role, "Signing")
            }
            other => unreachable!("unexpected: {other}"),
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
        mgr.sessions
            .get_mut("s1")
            .expect("session exists")
            .begin_termination();
        assert_eq!(mgr.active_session_count(), 2);
        mgr.terminate_session("s1", 9999, "t")
            .expect("should succeed");
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

        let mac_s1 = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h");
        assert!(
            mgr.process_message("s1", MessageDirection::Send, 0, "h", &mac_s1, 1, "t")
                .is_ok()
        );

        let mac_s2 = sign_msg(&mgr, "s2", MessageDirection::Send, 0, "h");
        assert!(
            mgr.process_message("s2", MessageDirection::Send, 0, "h", &mac_s2, 2, "t")
                .is_ok()
        );

        mgr.terminate_session("s1", 100, "t").unwrap();

        let mac_s2b = sign_msg(&mgr, "s2", MessageDirection::Send, 1, "h");
        assert!(
            mgr.process_message("s2", MessageDirection::Send, 1, "h", &mac_s2b, 3, "t")
                .is_ok()
        );
    }

    // ── AuthenticatedMessage fields ─────────────────────────────────

    #[test]
    fn test_message_fields() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let mac = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "hash123");
        let msg = mgr
            .process_message("s1", MessageDirection::Send, 0, "hash123", &mac, 1000, "t")
            .unwrap();

        assert_eq!(msg.session_id, "s1");
        assert_eq!(msg.sequence, 0);
        assert_eq!(msg.payload_hash, "hash123");
        assert_eq!(msg.verified_mac, mac);
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

        // Skip seq 0, try seq 5 — valid MAC but wrong sequence
        let mac5 = sign_msg(&mgr, "s1", MessageDirection::Send, 5, "h");
        let _ = mgr.process_message("s1", MessageDirection::Send, 5, "h", &mac5, 1, "t");

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
        let json = serde_json::to_string(&SessionState::Active).expect("serialize");
        let parsed: SessionState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, SessionState::Active);
    }

    #[test]
    fn test_session_config_serde() {
        let cfg = SessionConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: SessionConfig = serde_json::from_str(&json).expect("deserialize");
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
            1,
            [0xABu8; SIGNATURE_LEN],
        );
        s.activate(42);
        let json = serde_json::to_string(&s).expect("serialize");
        let parsed: AuthenticatedSession = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.session_id, "s1");
        assert_eq!(parsed.state, SessionState::Active);
        assert_eq!(parsed.handshake_mac, [0xABu8; SIGNATURE_LEN]);
        assert_eq!(parsed.last_activity_at, 42);
    }

    #[test]
    fn test_authenticated_session_serde_preserves_exhaustion_flags() {
        let mut s = AuthenticatedSession::new(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "e".into(),
            "sg".into(),
            0,
            1,
            [0xABu8; SIGNATURE_LEN],
        );
        s.send_seq = u64::MAX;
        s.recv_seq = u64::MAX;
        s.recv_seq_exhausted = true;

        let json = serde_json::to_string(&s).expect("serialize");
        assert!(
            json.contains("\"send_seq_exhausted\":false"),
            "serialize must preserve the pre-terminal send state explicitly"
        );
        assert!(
            json.contains("\"recv_seq_exhausted\":true"),
            "serialize must preserve the exhausted recv state explicitly"
        );

        let parsed: AuthenticatedSession = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.send_seq, u64::MAX);
        assert!(!parsed.send_seq_exhausted);
        assert_eq!(parsed.recv_seq, u64::MAX);
        assert!(parsed.recv_seq_exhausted);
    }

    #[test]
    fn test_message_direction_serde() {
        let json = serde_json::to_string(&MessageDirection::Send).expect("serialize");
        let parsed: MessageDirection = serde_json::from_str(&json).expect("deserialize");
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
        let json = serde_json::to_string(&e).expect("serialize");
        let parsed: SessionEvent = serde_json::from_str(&json).expect("deserialize");
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

    // ── Adversarial: handshake MAC verification ─────────────────────

    #[test]
    fn adversarial_forged_handshake_mac_rejected() {
        let mut mgr = default_manager();
        let forged_mac = [0xFF; SIGNATURE_LEN];
        let result = mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1000,
            "t".into(),
            forged_mac,
        );
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::AuthFailed { reason, .. } => {
                assert!(reason.contains("handshake MAC"));
            }
            other => unreachable!("expected AuthFailed, got: {other}"),
        }
    }

    #[test]
    fn adversarial_wrong_secret_handshake_rejected() {
        let wrong_secret = RootSecret::from_bytes([0xCC; 32]);
        let epoch = test_epoch();
        // Sign with wrong secret
        let mac = sign_handshake("s1", "c", "sv", "ek", "sk", epoch, 1000, &wrong_secret);
        let mut mgr = default_manager(); // uses test_root_secret()
        let result = mgr.establish_session(
            "s1".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1000,
            "t".into(),
            mac,
        );
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::AuthFailed { .. } => {}
            other => unreachable!("expected AuthFailed, got: {other}"),
        }
    }

    #[test]
    fn adversarial_session_id_swap_handshake_rejected() {
        let mut mgr = default_manager();
        let rs = test_root_secret();
        let epoch = test_epoch();
        // Sign for session "s1" but establish as "s2"
        let mac = sign_handshake("s1", "c", "sv", "ek", "sk", epoch, 1000, &rs);
        let result = mgr.establish_session(
            "s2".into(),
            "c".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1000,
            "t".into(),
            mac,
        );
        assert!(result.is_err());
    }

    #[test]
    fn adversarial_identity_swap_handshake_rejected() {
        let mut mgr = default_manager();
        let rs = test_root_secret();
        let epoch = test_epoch();
        // Sign for client "alice" but establish as "eve"
        let mac = sign_handshake("s1", "alice", "sv", "ek", "sk", epoch, 1000, &rs);
        let result = mgr.establish_session(
            "s1".into(),
            "eve".into(),
            "sv".into(),
            "ek".into(),
            "sk".into(),
            1000,
            "t".into(),
            mac,
        );
        assert!(result.is_err());
    }

    // ── Adversarial: message MAC verification ───────────────────────

    #[test]
    fn adversarial_forged_message_mac_rejected() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let forged = [0xFF; SIGNATURE_LEN];
        let result = mgr.process_message("s1", MessageDirection::Send, 0, "h", &forged, 2000, "t");
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::AuthFailed { reason, .. } => {
                assert!(reason.contains("message MAC"));
            }
            other => unreachable!("expected AuthFailed, got: {other}"),
        }
    }

    #[test]
    fn adversarial_payload_swap_under_valid_mac_rejected() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        // Sign for payload "real" but submit with payload "fake"
        let mac = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "real");
        let result = mgr.process_message("s1", MessageDirection::Send, 0, "fake", &mac, 2000, "t");
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::AuthFailed { .. } => {}
            other => unreachable!("expected AuthFailed, got: {other}"),
        }
    }

    #[test]
    fn adversarial_cross_session_mac_rejected() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");
        establish_test_session(&mut mgr, "s2");

        // Sign for session s1 but submit to session s2
        let mac_s1 = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h");
        let result = mgr.process_message("s2", MessageDirection::Send, 0, "h", &mac_s1, 2000, "t");
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::AuthFailed { .. } => {}
            other => unreachable!("expected AuthFailed, got: {other}"),
        }
    }

    #[test]
    fn adversarial_direction_swap_rejected() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        // Sign for Send but submit as Receive
        let mac = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "h");
        let result = mgr.process_message("s1", MessageDirection::Receive, 0, "h", &mac, 2000, "t");
        assert!(result.is_err());
    }

    #[test]
    fn adversarial_wrong_secret_message_rejected() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let wrong_secret = RootSecret::from_bytes([0xCC; 32]);
        let session = mgr.get_session("s1").unwrap();
        let mac = sign_session_message(
            "s1",
            MessageDirection::Send,
            0,
            "h",
            test_epoch(),
            &session.handshake_mac,
            &wrong_secret,
        );
        let result = mgr.process_message("s1", MessageDirection::Send, 0, "h", &mac, 2000, "t");
        assert!(result.is_err());
    }

    #[test]
    fn regression_opaque_signature_no_longer_accepted() {
        // The old API accepted any string as a "signature" and recorded it.
        // The new API requires a verified HMAC. This test ensures an arbitrary
        // byte pattern is rejected.
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let bogus = [0x42; SIGNATURE_LEN];
        let result = mgr.process_message("s1", MessageDirection::Send, 0, "h", &bogus, 2000, "t");
        assert!(result.is_err());
        match result.expect_err("should fail") {
            SessionError::AuthFailed { .. } => {}
            other => unreachable!("expected AuthFailed, got: {other}"),
        }
    }

    // ── Sign/verify round-trip ──────────────────────────────────────

    #[test]
    fn sign_verify_handshake_round_trip() {
        let rs = test_root_secret();
        let epoch = test_epoch();
        let mac = sign_handshake("sess-rt", "alice", "bob", "ek1", "sk1", epoch, 9999, &rs);
        let mut mgr = default_manager();
        let result = mgr.establish_session(
            "sess-rt".into(),
            "alice".into(),
            "bob".into(),
            "ek1".into(),
            "sk1".into(),
            9999,
            "t".into(),
            mac,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn sign_verify_message_round_trip() {
        let mut mgr = default_manager();
        establish_test_session(&mut mgr, "s1");

        let mac = sign_msg(&mgr, "s1", MessageDirection::Send, 0, "payload-hash");
        let result = mgr.process_message(
            "s1",
            MessageDirection::Send,
            0,
            "payload-hash",
            &mac,
            2000,
            "t",
        );
        assert!(result.is_ok());
    }

    // ── Regression: deserialize_mac rejects malformed hex ──────────

    fn session_json_with_mac(mac_hex: &str) -> String {
        format!(
            r#"{{"session_id":"s1","state":"Establishing","client_identity":"c","server_identity":"sv","encryption_key_id":"ek","signing_key_id":"sk","established_at":0,"last_activity_at":0,"send_seq":0,"recv_seq":0,"replay_window":0,"epoch":1,"handshake_mac":"{}"}}"#,
            mac_hex
        )
    }

    #[test]
    fn deserialize_mac_rejects_odd_length_hex() {
        // Old code would panic on odd-length hex due to out-of-bounds slice
        let json = session_json_with_mac(&"a".repeat(SIGNATURE_LEN * 2 - 1));
        let result: Result<AuthenticatedSession, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "odd-length hex must be rejected");
    }

    #[test]
    fn deserialize_mac_rejects_invalid_hex_chars() {
        let json = session_json_with_mac(&"zz".repeat(SIGNATURE_LEN));
        let result: Result<AuthenticatedSession, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "non-hex chars must be rejected");
    }

    #[test]
    fn deserialize_mac_accepts_valid_hex() {
        let valid_hex: String = (0..SIGNATURE_LEN)
            .map(|i| format!("{:02x}", i % 256))
            .collect();
        let json = session_json_with_mac(&valid_hex);
        let result: Result<AuthenticatedSession, _> = serde_json::from_str(&json);
        assert!(result.is_ok(), "valid hex must be accepted");
    }
}
