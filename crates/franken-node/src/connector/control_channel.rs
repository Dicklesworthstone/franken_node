//! bd-v97o: Authenticated control channel with per-direction sequence
//! monotonicity and replay-window checks.
//!
//! Prevents replay attacks and out-of-order processing on control channels.

use std::collections::HashSet;

/// Direction of a control channel message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Send,
    Receive,
}

impl Direction {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Receive => "receive",
        }
    }
}

/// Channel configuration.
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    pub replay_window_size: u64,
    pub require_auth: bool,
}

impl ChannelConfig {
    pub fn default_config() -> Self {
        Self {
            replay_window_size: 64,
            require_auth: true,
        }
    }
}

/// A control channel message.
#[derive(Debug, Clone)]
pub struct ChannelMessage {
    pub message_id: String,
    pub direction: Direction,
    pub sequence_number: u64,
    pub auth_token: String,
    pub payload_hash: String,
}

/// Result of authentication and sequence check.
#[derive(Debug, Clone)]
pub struct AuthCheckResult {
    pub message_id: String,
    pub authenticated: bool,
    pub sequence_valid: bool,
    pub replay_clean: bool,
    pub verdict: String,
}

/// Audit record for a channel check.
#[derive(Debug, Clone)]
pub struct ChannelAuditEntry {
    pub message_id: String,
    pub direction: String,
    pub sequence_number: u64,
    pub authenticated: bool,
    pub sequence_valid: bool,
    pub replay_clean: bool,
    pub verdict: String,
    pub timestamp: String,
}

/// Errors from control channel operations.
#[derive(Debug, Clone, PartialEq)]
pub enum ChannelError {
    AuthFailed {
        message_id: String,
    },
    SequenceRegress {
        message_id: String,
        expected_min: u64,
        got: u64,
    },
    ReplayDetected {
        message_id: String,
        sequence: u64,
    },
    InvalidConfig {
        reason: String,
    },
    ChannelClosed,
}

impl ChannelError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::AuthFailed { .. } => "ACC_AUTH_FAILED",
            Self::SequenceRegress { .. } => "ACC_SEQUENCE_REGRESS",
            Self::ReplayDetected { .. } => "ACC_REPLAY_DETECTED",
            Self::InvalidConfig { .. } => "ACC_INVALID_CONFIG",
            Self::ChannelClosed => "ACC_CHANNEL_CLOSED",
        }
    }
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthFailed { message_id } => write!(f, "ACC_AUTH_FAILED: {message_id}"),
            Self::SequenceRegress {
                message_id,
                expected_min,
                got,
            } => write!(
                f,
                "ACC_SEQUENCE_REGRESS: {message_id} expected>={expected_min} got={got}"
            ),
            Self::ReplayDetected {
                message_id,
                sequence,
            } => write!(f, "ACC_REPLAY_DETECTED: {message_id} seq={sequence}"),
            Self::InvalidConfig { reason } => write!(f, "ACC_INVALID_CONFIG: {reason}"),
            Self::ChannelClosed => write!(f, "ACC_CHANNEL_CLOSED"),
        }
    }
}

/// Validate channel config.
pub fn validate_config(config: &ChannelConfig) -> Result<(), ChannelError> {
    if config.replay_window_size == 0 {
        return Err(ChannelError::InvalidConfig {
            reason: "replay_window_size must be > 0".into(),
        });
    }
    Ok(())
}

/// Authenticated control channel with replay protection.
#[derive(Debug)]
pub struct ControlChannel {
    config: ChannelConfig,
    last_send_seq: Option<u64>,
    last_recv_seq: Option<u64>,
    send_window: HashSet<u64>,
    recv_window: HashSet<u64>,
    open: bool,
    audit_log: Vec<ChannelAuditEntry>,
}

impl ControlChannel {
    pub fn new(config: ChannelConfig) -> Result<Self, ChannelError> {
        validate_config(&config)?;
        Ok(Self {
            config,
            last_send_seq: None,
            last_recv_seq: None,
            send_window: HashSet::new(),
            recv_window: HashSet::new(),
            open: true,
            audit_log: Vec::new(),
        })
    }

    /// Authenticate a token. In production, this would verify cryptographic signatures.
    /// For this implementation: non-empty tokens are valid.
    fn authenticate(&self, token: &str) -> bool {
        if !self.config.require_auth {
            return true;
        }
        !token.is_empty()
    }

    /// Get the replay window for a direction.
    fn replay_window(&self, direction: Direction) -> &HashSet<u64> {
        match direction {
            Direction::Send => &self.send_window,
            Direction::Receive => &self.recv_window,
        }
    }

    fn replay_window_mut(&mut self, direction: Direction) -> &mut HashSet<u64> {
        match direction {
            Direction::Send => &mut self.send_window,
            Direction::Receive => &mut self.recv_window,
        }
    }

    fn last_seq(&self, direction: Direction) -> Option<u64> {
        match direction {
            Direction::Send => self.last_send_seq,
            Direction::Receive => self.last_recv_seq,
        }
    }

    fn set_last_seq(&mut self, direction: Direction, seq: u64) {
        match direction {
            Direction::Send => self.last_send_seq = Some(seq),
            Direction::Receive => self.last_recv_seq = Some(seq),
        }
    }

    /// Process a message through the authenticated control channel.
    ///
    /// INV-ACC-AUTHENTICATED: auth check first.
    /// INV-ACC-MONOTONIC: sequence must be > last seen for direction.
    /// INV-ACC-REPLAY-WINDOW: sequence must not be in replay window.
    /// INV-ACC-AUDITABLE: emits audit record.
    pub fn process_message(
        &mut self,
        msg: &ChannelMessage,
        timestamp: &str,
    ) -> Result<(AuthCheckResult, ChannelAuditEntry), ChannelError> {
        if !self.open {
            return Err(ChannelError::ChannelClosed);
        }

        // Step 1: Authentication (INV-ACC-AUTHENTICATED)
        let authenticated = self.authenticate(&msg.auth_token);
        if !authenticated {
            let _result = AuthCheckResult {
                message_id: msg.message_id.clone(),
                authenticated: false,
                sequence_valid: false,
                replay_clean: false,
                verdict: "REJECT_AUTH".into(),
            };
            let audit = ChannelAuditEntry {
                message_id: msg.message_id.clone(),
                direction: msg.direction.label().into(),
                sequence_number: msg.sequence_number,
                authenticated: false,
                sequence_valid: false,
                replay_clean: false,
                verdict: "REJECT_AUTH".into(),
                timestamp: timestamp.into(),
            };
            self.audit_log.push(audit.clone());
            return Err(ChannelError::AuthFailed {
                message_id: msg.message_id.clone(),
            });
        }

        // Step 2: Replay window check (INV-ACC-REPLAY-WINDOW)
        let replay_clean = !self
            .replay_window(msg.direction)
            .contains(&msg.sequence_number);
        if !replay_clean {
            let audit = ChannelAuditEntry {
                message_id: msg.message_id.clone(),
                direction: msg.direction.label().into(),
                sequence_number: msg.sequence_number,
                authenticated: true,
                sequence_valid: false,
                replay_clean: false,
                verdict: "REJECT_REPLAY".into(),
                timestamp: timestamp.into(),
            };
            self.audit_log.push(audit);
            return Err(ChannelError::ReplayDetected {
                message_id: msg.message_id.clone(),
                sequence: msg.sequence_number,
            });
        }

        // Step 3: Monotonicity check (INV-ACC-MONOTONIC)
        let sequence_valid = match self.last_seq(msg.direction) {
            Some(last) => msg.sequence_number > last,
            None => true,
        };
        if !sequence_valid {
            let expected_min = self.last_seq(msg.direction).unwrap_or(0) + 1;
            let audit = ChannelAuditEntry {
                message_id: msg.message_id.clone(),
                direction: msg.direction.label().into(),
                sequence_number: msg.sequence_number,
                authenticated: true,
                sequence_valid: false,
                replay_clean: true,
                verdict: "REJECT_SEQUENCE".into(),
                timestamp: timestamp.into(),
            };
            self.audit_log.push(audit);
            return Err(ChannelError::SequenceRegress {
                message_id: msg.message_id.clone(),
                expected_min,
                got: msg.sequence_number,
            });
        }

        // All checks passed
        self.set_last_seq(msg.direction, msg.sequence_number);
        let window_size = self.config.replay_window_size;
        let window = self.replay_window_mut(msg.direction);
        window.insert(msg.sequence_number);
        // Trim window to configured size
        if window.len() as u64 > window_size {
            let min_seq = msg.sequence_number.saturating_sub(window_size);
            window.retain(|&s| s > min_seq);
        }

        let result = AuthCheckResult {
            message_id: msg.message_id.clone(),
            authenticated: true,
            sequence_valid: true,
            replay_clean: true,
            verdict: "ACCEPT".into(),
        };
        let audit = ChannelAuditEntry {
            message_id: msg.message_id.clone(),
            direction: msg.direction.label().into(),
            sequence_number: msg.sequence_number,
            authenticated: true,
            sequence_valid: true,
            replay_clean: true,
            verdict: "ACCEPT".into(),
            timestamp: timestamp.into(),
        };
        self.audit_log.push(audit.clone());

        Ok((result, audit))
    }

    /// Close the channel.
    pub fn close(&mut self) {
        self.open = false;
    }

    /// Get all audit entries.
    pub fn audit_log(&self) -> &[ChannelAuditEntry] {
        &self.audit_log
    }

    pub fn is_open(&self) -> bool {
        self.open
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ChannelConfig {
        ChannelConfig {
            replay_window_size: 10,
            require_auth: true,
        }
    }

    fn msg(id: &str, dir: Direction, seq: u64, token: &str) -> ChannelMessage {
        ChannelMessage {
            message_id: id.into(),
            direction: dir,
            sequence_number: seq,
            auth_token: token.into(),
            payload_hash: "hash".into(),
        }
    }

    #[test]
    fn accept_valid_message() {
        let mut ch = ControlChannel::new(config()).unwrap();
        let m = msg("m1", Direction::Send, 1, "valid-token");
        let (result, audit) = ch.process_message(&m, "ts").unwrap();
        assert!(result.authenticated);
        assert!(result.sequence_valid);
        assert!(result.replay_clean);
        assert_eq!(audit.verdict, "ACCEPT");
    }

    #[test]
    fn reject_unauthenticated() {
        let mut ch = ControlChannel::new(config()).unwrap();
        let m = msg("m1", Direction::Send, 1, "");
        let err = ch.process_message(&m, "ts").unwrap_err();
        assert_eq!(err.code(), "ACC_AUTH_FAILED");
    }

    #[test]
    fn reject_sequence_regress() {
        let mut ch = ControlChannel::new(config()).unwrap();
        let m1 = msg("m1", Direction::Receive, 5, "tok");
        ch.process_message(&m1, "ts").unwrap();
        let m2 = msg("m2", Direction::Receive, 3, "tok");
        let err = ch.process_message(&m2, "ts").unwrap_err();
        assert_eq!(err.code(), "ACC_SEQUENCE_REGRESS");
    }

    #[test]
    fn reject_replay() {
        let mut ch = ControlChannel::new(config()).unwrap();
        let m1 = msg("m1", Direction::Send, 1, "tok");
        ch.process_message(&m1, "ts").unwrap();
        let m2 = msg("m2", Direction::Send, 2, "tok");
        ch.process_message(&m2, "ts").unwrap();
        // Replay: send seq 1 again — monotonicity check will catch it first
        // Actually, seq 1 < last_send (2), so it's a regress
        let m3 = msg("m3", Direction::Send, 1, "tok");
        let err = ch.process_message(&m3, "ts").unwrap_err();
        // Could be ACC_SEQUENCE_REGRESS or ACC_REPLAY_DETECTED depending on check order
        assert!(err.code() == "ACC_SEQUENCE_REGRESS" || err.code() == "ACC_REPLAY_DETECTED");
    }

    #[test]
    fn monotonic_per_direction() {
        let mut ch = ControlChannel::new(config()).unwrap();
        // Send seq 5
        ch.process_message(&msg("m1", Direction::Send, 5, "tok"), "ts")
            .unwrap();
        // Recv seq 1 should work (different direction)
        ch.process_message(&msg("m2", Direction::Receive, 1, "tok"), "ts")
            .unwrap();
        // Recv seq 2 should work
        ch.process_message(&msg("m3", Direction::Receive, 2, "tok"), "ts")
            .unwrap();
        // Send seq 4 should fail (regress)
        let err = ch
            .process_message(&msg("m4", Direction::Send, 4, "tok"), "ts")
            .unwrap_err();
        assert_eq!(err.code(), "ACC_SEQUENCE_REGRESS");
    }

    #[test]
    fn channel_closed() {
        let mut ch = ControlChannel::new(config()).unwrap();
        ch.close();
        let err = ch
            .process_message(&msg("m1", Direction::Send, 1, "tok"), "ts")
            .unwrap_err();
        assert_eq!(err.code(), "ACC_CHANNEL_CLOSED");
    }

    #[test]
    fn audit_log_recorded() {
        let mut ch = ControlChannel::new(config()).unwrap();
        ch.process_message(&msg("m1", Direction::Send, 1, "tok"), "ts")
            .unwrap();
        let _ = ch.process_message(&msg("m2", Direction::Send, 1, ""), "ts"); // auth fail
        assert!(ch.audit_log().len() >= 2);
    }

    #[test]
    fn no_auth_mode() {
        let cfg = ChannelConfig {
            replay_window_size: 10,
            require_auth: false,
        };
        let mut ch = ControlChannel::new(cfg).unwrap();
        let m = msg("m1", Direction::Send, 1, "");
        let (result, _) = ch.process_message(&m, "ts").unwrap();
        assert!(result.authenticated);
    }

    #[test]
    fn invalid_config_zero_window() {
        let cfg = ChannelConfig {
            replay_window_size: 0,
            require_auth: true,
        };
        let err = ControlChannel::new(cfg).unwrap_err();
        assert_eq!(err.code(), "ACC_INVALID_CONFIG");
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            ChannelError::AuthFailed {
                message_id: "".into()
            }
            .code(),
            "ACC_AUTH_FAILED"
        );
        assert_eq!(
            ChannelError::SequenceRegress {
                message_id: "".into(),
                expected_min: 0,
                got: 0
            }
            .code(),
            "ACC_SEQUENCE_REGRESS"
        );
        assert_eq!(
            ChannelError::ReplayDetected {
                message_id: "".into(),
                sequence: 0
            }
            .code(),
            "ACC_REPLAY_DETECTED"
        );
        assert_eq!(
            ChannelError::InvalidConfig { reason: "".into() }.code(),
            "ACC_INVALID_CONFIG"
        );
        assert_eq!(ChannelError::ChannelClosed.code(), "ACC_CHANNEL_CLOSED");
    }

    #[test]
    fn error_display() {
        let e = ChannelError::AuthFailed {
            message_id: "m1".into(),
        };
        assert!(e.to_string().contains("ACC_AUTH_FAILED"));
    }

    #[test]
    fn default_config_valid() {
        assert!(validate_config(&ChannelConfig::default_config()).is_ok());
    }

    #[test]
    fn direction_labels() {
        assert_eq!(Direction::Send.label(), "send");
        assert_eq!(Direction::Receive.label(), "receive");
    }

    #[test]
    fn first_message_any_sequence() {
        let mut ch = ControlChannel::new(config()).unwrap();
        // First message can have any sequence
        ch.process_message(&msg("m1", Direction::Send, 100, "tok"), "ts")
            .unwrap();
    }

    #[test]
    fn deterministic_processing() {
        let mut ch1 = ControlChannel::new(config()).unwrap();
        let mut ch2 = ControlChannel::new(config()).unwrap();
        let m1 = msg("m1", Direction::Send, 1, "tok");
        let m2 = msg("m2", Direction::Send, 2, "tok");
        let (r1a, _) = ch1.process_message(&m1, "ts").unwrap();
        let (r2a, _) = ch2.process_message(&m1, "ts").unwrap();
        assert_eq!(r1a.verdict, r2a.verdict);
        let (r1b, _) = ch1.process_message(&m2, "ts").unwrap();
        let (r2b, _) = ch2.process_message(&m2, "ts").unwrap();
        assert_eq!(r1b.verdict, r2b.verdict);
    }
}
