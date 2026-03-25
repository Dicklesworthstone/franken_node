//! bd-v97o / bd-3cvu: Authenticated control channel with transcript-bound
//! capability verification, per-direction sequence monotonicity, and
//! replay-window checks.
//!
//! Every accepted frame is backed by an HMAC-SHA256 credential that binds:
//! channel_id, subject_id, audience, direction, sequence_number,
//! payload_hash, epoch, and nonce into a domain-separated transcript.
//! The `!token.is_empty()` shortcut is gone; real verification is mandatory.

use crate::control_plane::control_epoch::ControlEpoch;
use crate::security::constant_time::ct_eq_bytes;
use crate::security::epoch_scoped_keys::{RootSecret, SIGNATURE_LEN, derive_epoch_key};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeSet;

type HmacSha256 = Hmac<Sha256>;

const MAX_AUDIT_LOG_ENTRIES: usize = 1024;

/// Domain separator for control-channel transcript HMAC.
const CONTROL_CHANNEL_DOMAIN: &str = "control_channel";

/// Domain separator prefix inside the HMAC computation.
const TRANSCRIPT_HMAC_PREFIX: &[u8] = b"control_channel_transcript_v1:";

/// Stable event codes for structured logging.
pub mod event_codes {
    pub const CONTROL_AUTH_ACCEPT: &str = "CONTROL_AUTH_ACCEPT";
    pub const CONTROL_AUTH_REJECT: &str = "CONTROL_AUTH_REJECT";
    pub const CONTROL_AUTH_REPLAY: &str = "CONTROL_AUTH_REPLAY";
    pub const CONTROL_AUTH_SEQ_REGRESS: &str = "CONTROL_AUTH_SEQ_REGRESS";
    pub const CONTROL_AUTH_CLOSED: &str = "CONTROL_AUTH_CLOSED";
}

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

    /// Single-byte direction tag for transcript binding.
    fn tag(&self) -> u8 {
        match self {
            Self::Send => 0x01,
            Self::Receive => 0x02,
        }
    }
}

/// Channel configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelConfig {
    pub replay_window_size: u64,
    pub require_auth: bool,
    /// Channel identity used in transcript binding.
    pub channel_id: String,
    /// Expected audience (receiving service identity).
    pub audience: String,
}

impl ChannelConfig {
    pub fn default_config() -> Self {
        Self {
            replay_window_size: 64,
            require_auth: true,
            channel_id: "default-channel".into(),
            audience: "default-audience".into(),
        }
    }
}

/// Transcript-bound credential for a control channel frame.
///
/// Replaces the old bare `auth_token: String` with structured HMAC evidence.
/// The credential binds: channel_id, subject_id, audience, direction,
/// sequence_number, payload_hash, epoch, and nonce.
#[derive(Debug, Clone)]
pub struct ChannelCredential {
    /// Identity of the sender (subject).
    pub subject_id: String,
    /// Epoch under which the credential was issued.
    pub epoch: ControlEpoch,
    /// Unique nonce to prevent cross-message credential reuse.
    pub nonce: [u8; 16],
    /// HMAC-SHA256 over the transcript preimage.
    pub mac: [u8; SIGNATURE_LEN],
}

/// A control channel message.
#[derive(Debug, Clone)]
pub struct ChannelMessage {
    pub message_id: String,
    pub direction: Direction,
    pub sequence_number: u64,
    /// Transcript-bound credential (replaces bare auth_token).
    pub credential: ChannelCredential,
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
    /// Reason code for denials.
    pub reason_code: Option<String>,
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
    /// Subject identity from the credential.
    pub subject_id: String,
    /// Epoch from the credential.
    pub epoch: u64,
    /// Reason code for denials.
    pub reason_code: Option<String>,
}

/// Errors from control channel operations.
#[derive(Debug, Clone, PartialEq)]
pub enum ChannelError {
    AuthFailed {
        message_id: String,
        reason: String,
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

    /// Whether the caller may retry (with a fresh credential, for instance).
    pub fn retryable(&self) -> bool {
        match self {
            Self::AuthFailed { .. } => true,
            Self::SequenceRegress { .. } => false,
            Self::ReplayDetected { .. } => false,
            Self::InvalidConfig { .. } => false,
            Self::ChannelClosed => false,
        }
    }
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthFailed { message_id, reason } => {
                write!(f, "ACC_AUTH_FAILED: {message_id} reason={reason}")
            }
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
    if config.channel_id.is_empty() {
        return Err(ChannelError::InvalidConfig {
            reason: "channel_id must not be empty".into(),
        });
    }
    if config.audience.is_empty() {
        return Err(ChannelError::InvalidConfig {
            reason: "audience must not be empty".into(),
        });
    }
    Ok(())
}

/// Input fields for building a transcript preimage.
///
/// Bundles the parameters that are bound into the HMAC to satisfy clippy's
/// argument-count lint while keeping each field named and explicit.
pub struct TranscriptFields<'a> {
    pub channel_id: &'a str,
    pub subject_id: &'a str,
    pub audience: &'a str,
    pub direction: Direction,
    pub sequence_number: u64,
    pub payload_hash: &'a str,
    pub epoch: ControlEpoch,
    pub nonce: &'a [u8; 16],
}

/// Build the transcript preimage that the HMAC binds.
///
/// Format (all variable-length fields are length-prefixed):
///   len(channel_id) || channel_id ||
///   len(subject_id) || subject_id ||
///   len(audience)   || audience   ||
///   direction_tag   ||
///   sequence_number (8 bytes LE) ||
///   len(payload_hash) || payload_hash ||
///   epoch (8 bytes LE) ||
///   nonce (16 bytes)
fn build_transcript_preimage(fields: &TranscriptFields<'_>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // Length-prefixed fields to prevent delimiter collision attacks.
    fn append_lp(buf: &mut Vec<u8>, field: &[u8]) {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field);
    }

    append_lp(&mut buf, fields.channel_id.as_bytes());
    append_lp(&mut buf, fields.subject_id.as_bytes());
    append_lp(&mut buf, fields.audience.as_bytes());
    buf.push(fields.direction.tag());
    buf.extend_from_slice(&fields.sequence_number.to_le_bytes());
    append_lp(&mut buf, fields.payload_hash.as_bytes());
    buf.extend_from_slice(&fields.epoch.value().to_le_bytes());
    buf.extend_from_slice(fields.nonce);
    buf
}

/// Compute the HMAC over a transcript preimage using the epoch-scoped key.
fn compute_transcript_mac(
    preimage: &[u8],
    epoch: ControlEpoch,
    root_secret: &RootSecret,
) -> [u8; SIGNATURE_LEN] {
    let derived_key = derive_epoch_key(root_secret, epoch, CONTROL_CHANNEL_DOMAIN);
    let mut hmac =
        HmacSha256::new_from_slice(derived_key.as_bytes()).expect("HMAC key length is constant");
    hmac.update(TRANSCRIPT_HMAC_PREFIX);
    hmac.update(preimage);
    let result = hmac.finalize().into_bytes();
    let mut mac = [0u8; SIGNATURE_LEN];
    mac.copy_from_slice(&result);
    mac
}

/// Sign a control-channel message and produce a `ChannelCredential`.
///
/// The caller provides the root secret and epoch; the function derives the
/// epoch-scoped HMAC key and computes the transcript-bound MAC.
#[allow(clippy::too_many_arguments)]
pub fn sign_channel_message(
    config: &ChannelConfig,
    subject_id: &str,
    direction: Direction,
    sequence_number: u64,
    payload_hash: &str,
    epoch: ControlEpoch,
    nonce: [u8; 16],
    root_secret: &RootSecret,
) -> ChannelCredential {
    let fields = TranscriptFields {
        channel_id: &config.channel_id,
        subject_id,
        audience: &config.audience,
        direction,
        sequence_number,
        payload_hash,
        epoch,
        nonce: &nonce,
    };
    let preimage = build_transcript_preimage(&fields);
    let mac = compute_transcript_mac(&preimage, epoch, root_secret);

    ChannelCredential {
        subject_id: subject_id.into(),
        epoch,
        nonce,
        mac,
    }
}

/// Authenticated control channel with transcript-bound capability
/// verification and replay protection.
#[derive(Debug)]
pub struct ControlChannel {
    config: ChannelConfig,
    /// Root secret for HMAC key derivation — zeroized on drop.
    root_secret: RootSecret,
    last_send_seq: Option<u64>,
    last_recv_seq: Option<u64>,
    send_window: BTreeSet<u64>,
    recv_window: BTreeSet<u64>,
    /// Nonces seen in the current epoch for cross-message replay detection.
    seen_nonces: BTreeSet<[u8; 16]>,
    open: bool,
    audit_log: Vec<ChannelAuditEntry>,
}

use crate::capacity_defaults::aliases::MAX_SEEN_NONCES;

impl ControlChannel {
    pub fn new(config: ChannelConfig, root_secret: RootSecret) -> Result<Self, ChannelError> {
        validate_config(&config)?;
        Ok(Self {
            config,
            root_secret,
            last_send_seq: None,
            last_recv_seq: None,
            send_window: BTreeSet::new(),
            recv_window: BTreeSet::new(),
            seen_nonces: BTreeSet::new(),
            open: true,
            audit_log: Vec::new(),
        })
    }

    /// Verify a transcript-bound credential.
    ///
    /// Recomputes the HMAC from the message fields and the channel's root
    /// secret, then compares in constant time.  Returns an error string on
    /// failure for structured logging.
    fn verify_credential(&self, msg: &ChannelMessage) -> Result<(), String> {
        if !self.config.require_auth {
            return Ok(());
        }

        // Audience must match this channel's configured audience.
        // (The credential does not carry audience explicitly; it is bound
        // into the transcript via the channel config.)

        let fields = TranscriptFields {
            channel_id: &self.config.channel_id,
            subject_id: &msg.credential.subject_id,
            audience: &self.config.audience,
            direction: msg.direction,
            sequence_number: msg.sequence_number,
            payload_hash: &msg.payload_hash,
            epoch: msg.credential.epoch,
            nonce: &msg.credential.nonce,
        };
        let preimage = build_transcript_preimage(&fields);
        let expected = compute_transcript_mac(&preimage, msg.credential.epoch, &self.root_secret);

        if !ct_eq_bytes(&msg.credential.mac, &expected) {
            return Err("transcript_mac_mismatch".into());
        }

        // Nonce reuse check (cross-message replay within the same epoch).
        if self.seen_nonces.contains(&msg.credential.nonce) {
            return Err("nonce_reuse_detected".into());
        }

        Ok(())
    }

    /// Get the replay window for a direction.
    fn replay_window(&self, direction: Direction) -> &BTreeSet<u64> {
        match direction {
            Direction::Send => &self.send_window,
            Direction::Receive => &self.recv_window,
        }
    }

    fn replay_window_mut(&mut self, direction: Direction) -> &mut BTreeSet<u64> {
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

    /// Append an audit entry with deterministic oldest-first eviction once
    /// the bounded capacity is reached.
    fn push_audit_entry(&mut self, entry: ChannelAuditEntry) {
        push_bounded(&mut self.audit_log, entry, MAX_AUDIT_LOG_ENTRIES);
    }

    /// Record nonce with bounded eviction.
    fn record_nonce(&mut self, nonce: [u8; 16]) {
        self.seen_nonces.insert(nonce);
        // Evict oldest nonces when capacity is exceeded.
        while self.seen_nonces.len() > MAX_SEEN_NONCES {
            // BTreeSet iteration is sorted; remove the smallest.
            if let Some(&oldest) = self.seen_nonces.iter().next() {
                self.seen_nonces.remove(&oldest);
            }
        }
    }

    /// Build an audit entry with common fields filled from the message.
    fn make_audit(
        msg: &ChannelMessage,
        timestamp: &str,
        authenticated: bool,
        sequence_valid: bool,
        replay_clean: bool,
        verdict: &str,
        reason_code: Option<&str>,
    ) -> ChannelAuditEntry {
        ChannelAuditEntry {
            message_id: msg.message_id.clone(),
            direction: msg.direction.label().into(),
            sequence_number: msg.sequence_number,
            authenticated,
            sequence_valid,
            replay_clean,
            verdict: verdict.into(),
            timestamp: timestamp.into(),
            subject_id: msg.credential.subject_id.clone(),
            epoch: msg.credential.epoch.value(),
            reason_code: reason_code.map(String::from),
        }
    }

    /// Process a message through the authenticated control channel.
    ///
    /// INV-ACC-AUTHENTICATED: transcript-bound HMAC check first.
    /// INV-ACC-MONOTONIC: sequence must be > last seen for direction.
    /// INV-ACC-REPLAY-WINDOW: sequence must not be in replay window.
    /// INV-ACC-NONCE: nonce must not have been seen before.
    /// INV-ACC-AUDITABLE: emits audit record for every decision.
    pub fn process_message(
        &mut self,
        msg: &ChannelMessage,
        timestamp: &str,
    ) -> Result<(AuthCheckResult, ChannelAuditEntry), ChannelError> {
        if !self.open {
            return Err(ChannelError::ChannelClosed);
        }

        // Step 1: Transcript-bound authentication (INV-ACC-AUTHENTICATED)
        if let Err(reason) = self.verify_credential(msg) {
            let audit = Self::make_audit(
                msg,
                timestamp,
                false,
                false,
                false,
                "REJECT_AUTH",
                Some(&reason),
            );
            self.push_audit_entry(audit.clone());
            return Err(ChannelError::AuthFailed {
                message_id: msg.message_id.clone(),
                reason,
            });
        }

        // Step 2: Replay window check (INV-ACC-REPLAY-WINDOW)
        let replay_clean = !self
            .replay_window(msg.direction)
            .contains(&msg.sequence_number);
        if !replay_clean {
            let audit = Self::make_audit(msg, timestamp, true, false, false, "REJECT_REPLAY", None);
            self.push_audit_entry(audit);
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
            let expected_min = self.last_seq(msg.direction).unwrap_or(0).saturating_add(1);
            let audit =
                Self::make_audit(msg, timestamp, true, false, true, "REJECT_SEQUENCE", None);
            self.push_audit_entry(audit);
            return Err(ChannelError::SequenceRegress {
                message_id: msg.message_id.clone(),
                expected_min,
                got: msg.sequence_number,
            });
        }

        // All checks passed — update state.
        self.set_last_seq(msg.direction, msg.sequence_number);
        self.record_nonce(msg.credential.nonce);

        let window_size = self.config.replay_window_size;
        let min_retained_seq = msg
            .sequence_number
            .saturating_sub(window_size.saturating_sub(1));
        let window = self.replay_window_mut(msg.direction);
        window.insert(msg.sequence_number);
        window.retain(|&s| s >= min_retained_seq);

        let result = AuthCheckResult {
            message_id: msg.message_id.clone(),
            authenticated: true,
            sequence_valid: true,
            replay_clean: true,
            verdict: "ACCEPT".into(),
            reason_code: None,
        };
        let audit = Self::make_audit(msg, timestamp, true, true, true, "ACCEPT", None);
        self.push_audit_entry(audit.clone());

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

/// Push an item to a bounded Vec, evicting oldest entries if at capacity.
fn push_bounded<T>(vec: &mut Vec<T>, item: T, max: usize) {
    vec.push(item);
    if vec.len() > max {
        let overflow = vec.len() - max;
        vec.drain(0..overflow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> RootSecret {
        RootSecret::from_bytes([0xAB; SIGNATURE_LEN])
    }

    fn config() -> ChannelConfig {
        ChannelConfig {
            replay_window_size: 10,
            require_auth: true,
            channel_id: "test-channel".into(),
            audience: "test-audience".into(),
        }
    }

    /// Build a validly-signed message for the test channel.
    fn signed_msg(id: &str, dir: Direction, seq: u64) -> ChannelMessage {
        let nonce = {
            let mut n = [0u8; 16];
            let bytes = format!("{id}:{seq}");
            for (i, b) in bytes.as_bytes().iter().enumerate() {
                if i < 16 {
                    n[i] = *b;
                }
            }
            n
        };
        let payload_hash = "test-payload-hash";
        let epoch = ControlEpoch::new(1);
        let cfg = config();
        let credential = sign_channel_message(
            &cfg,
            "test-subject",
            dir,
            seq,
            payload_hash,
            epoch,
            nonce,
            &test_secret(),
        );
        ChannelMessage {
            message_id: id.into(),
            direction: dir,
            sequence_number: seq,
            credential,
            payload_hash: payload_hash.into(),
        }
    }

    /// Build a message with a forged/invalid credential.
    fn forged_msg(id: &str, dir: Direction, seq: u64) -> ChannelMessage {
        let credential = ChannelCredential {
            subject_id: "attacker".into(),
            epoch: ControlEpoch::new(1),
            nonce: [0xFF; 16],
            mac: [0x00; SIGNATURE_LEN], // invalid MAC
        };
        ChannelMessage {
            message_id: id.into(),
            direction: dir,
            sequence_number: seq,
            credential,
            payload_hash: "test-payload-hash".into(),
        }
    }

    // ---------------------------------------------------------------
    // Core functionality tests
    // ---------------------------------------------------------------

    #[test]
    fn accept_valid_message() {
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        let m = signed_msg("m1", Direction::Send, 1);
        let (result, audit) = ch.process_message(&m, "ts").unwrap();
        assert!(result.authenticated);
        assert!(result.sequence_valid);
        assert!(result.replay_clean);
        assert_eq!(audit.verdict, "ACCEPT");
        assert_eq!(audit.subject_id, "test-subject");
        assert_eq!(audit.epoch, 1);
    }

    #[test]
    fn reject_forged_credential() {
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        let m = forged_msg("m1", Direction::Send, 1);
        let err = ch.process_message(&m, "ts").unwrap_err();
        assert_eq!(err.code(), "ACC_AUTH_FAILED");
        // Verify audit recorded the failure.
        assert_eq!(ch.audit_log().len(), 1);
        assert!(!ch.audit_log()[0].authenticated);
    }

    #[test]
    fn reject_sequence_regress() {
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        ch.process_message(&signed_msg("m1", Direction::Receive, 5), "ts")
            .unwrap();
        let err = ch
            .process_message(&signed_msg("m2", Direction::Receive, 3), "ts")
            .unwrap_err();
        assert_eq!(err.code(), "ACC_SEQUENCE_REGRESS");
    }

    #[test]
    fn reject_replay_same_sequence() {
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        ch.process_message(&signed_msg("m1", Direction::Send, 1), "ts")
            .unwrap();
        ch.process_message(&signed_msg("m2", Direction::Send, 2), "ts")
            .unwrap();
        // Attempt seq 1 again — monotonicity catches it before replay window.
        let err = ch
            .process_message(&signed_msg("m3", Direction::Send, 1), "ts")
            .unwrap_err();
        assert!(err.code() == "ACC_SEQUENCE_REGRESS" || err.code() == "ACC_REPLAY_DETECTED");
    }

    #[test]
    fn replay_window_keeps_zero_based_sequences_until_the_window_moves_past_them() {
        let mut cfg = config();
        cfg.replay_window_size = 2;
        let mut ch = ControlChannel::new(cfg, test_secret()).unwrap();

        ch.process_message(&signed_msg("m0", Direction::Send, 0), "ts")
            .unwrap();
        ch.process_message(&signed_msg("m1", Direction::Send, 1), "ts")
            .unwrap();

        let err = ch
            .process_message(&signed_msg("m0-replay", Direction::Send, 0), "ts")
            .unwrap_err();

        match err {
            ChannelError::ReplayDetected { sequence, .. } => assert_eq!(sequence, 0),
            other => unreachable!("expected replay detection, got {other:?}"),
        }
    }

    #[test]
    fn monotonic_per_direction() {
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        ch.process_message(&signed_msg("m1", Direction::Send, 5), "ts")
            .unwrap();
        // Different direction: seq 1 is fine.
        ch.process_message(&signed_msg("m2", Direction::Receive, 1), "ts")
            .unwrap();
        ch.process_message(&signed_msg("m3", Direction::Receive, 2), "ts")
            .unwrap();
        // Same direction as m1: seq 4 is a regress.
        let err = ch
            .process_message(&signed_msg("m4", Direction::Send, 4), "ts")
            .unwrap_err();
        assert_eq!(err.code(), "ACC_SEQUENCE_REGRESS");
    }

    #[test]
    fn channel_closed() {
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        ch.close();
        let err = ch
            .process_message(&signed_msg("m1", Direction::Send, 1), "ts")
            .unwrap_err();
        assert_eq!(err.code(), "ACC_CHANNEL_CLOSED");
    }

    #[test]
    fn audit_log_recorded() {
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        ch.process_message(&signed_msg("m1", Direction::Send, 1), "ts")
            .unwrap();
        let _ = ch.process_message(&forged_msg("m2", Direction::Send, 2), "ts");
        assert_eq!(ch.audit_log().len(), 2);
    }

    #[test]
    fn no_auth_mode_accepts_invalid_mac() {
        let cfg = ChannelConfig {
            replay_window_size: 10,
            require_auth: false,
            channel_id: "noauth-ch".into(),
            audience: "noauth-aud".into(),
        };
        let mut ch = ControlChannel::new(cfg, test_secret()).unwrap();
        let m = forged_msg("m1", Direction::Send, 1);
        let (result, _) = ch.process_message(&m, "ts").unwrap();
        assert!(result.authenticated);
    }

    #[test]
    fn invalid_config_zero_window() {
        let cfg = ChannelConfig {
            replay_window_size: 0,
            require_auth: true,
            channel_id: "ch".into(),
            audience: "aud".into(),
        };
        let err = ControlChannel::new(cfg, test_secret()).unwrap_err();
        assert_eq!(err.code(), "ACC_INVALID_CONFIG");
    }

    #[test]
    fn invalid_config_empty_channel_id() {
        let cfg = ChannelConfig {
            replay_window_size: 10,
            require_auth: true,
            channel_id: "".into(),
            audience: "aud".into(),
        };
        let err = ControlChannel::new(cfg, test_secret()).unwrap_err();
        assert_eq!(err.code(), "ACC_INVALID_CONFIG");
    }

    #[test]
    fn invalid_config_empty_audience() {
        let cfg = ChannelConfig {
            replay_window_size: 10,
            require_auth: true,
            channel_id: "ch".into(),
            audience: "".into(),
        };
        let err = ControlChannel::new(cfg, test_secret()).unwrap_err();
        assert_eq!(err.code(), "ACC_INVALID_CONFIG");
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            ChannelError::AuthFailed {
                message_id: "".into(),
                reason: "test".into(),
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
            reason: "bad_mac".into(),
        };
        assert!(e.to_string().contains("ACC_AUTH_FAILED"));
        assert!(e.to_string().contains("bad_mac"));
    }

    #[test]
    fn error_retryable() {
        assert!(
            ChannelError::AuthFailed {
                message_id: "".into(),
                reason: "".into(),
            }
            .retryable()
        );
        assert!(
            !ChannelError::SequenceRegress {
                message_id: "".into(),
                expected_min: 0,
                got: 0,
            }
            .retryable()
        );
        assert!(!ChannelError::ChannelClosed.retryable());
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
    fn direction_tags_distinct() {
        assert_ne!(Direction::Send.tag(), Direction::Receive.tag());
    }

    #[test]
    fn first_message_any_sequence() {
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        ch.process_message(&signed_msg("m1", Direction::Send, 100), "ts")
            .unwrap();
    }

    #[test]
    fn sequence_regress_after_max_sequence_does_not_overflow() {
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        ch.process_message(&signed_msg("m1", Direction::Send, u64::MAX), "ts")
            .unwrap();

        let err = ch
            .process_message(&signed_msg("m2", Direction::Send, u64::MAX - 1), "ts")
            .unwrap_err();

        match err {
            ChannelError::SequenceRegress {
                expected_min, got, ..
            } => {
                assert_eq!(expected_min, u64::MAX);
                assert_eq!(got, u64::MAX - 1);
            }
            other => unreachable!("expected sequence regress, got {other:?}"),
        }
    }

    #[test]
    fn deterministic_processing() {
        let mut ch1 = ControlChannel::new(config(), test_secret()).unwrap();
        let mut ch2 = ControlChannel::new(config(), test_secret()).unwrap();
        let m1 = signed_msg("m1", Direction::Send, 1);
        let m2 = signed_msg("m2", Direction::Send, 2);
        let (r1a, _) = ch1.process_message(&m1, "ts").unwrap();
        let (r2a, _) = ch2.process_message(&m1, "ts").unwrap();
        assert_eq!(r1a.verdict, r2a.verdict);
        let (r1b, _) = ch1.process_message(&m2, "ts").unwrap();
        let (r2b, _) = ch2.process_message(&m2, "ts").unwrap();
        assert_eq!(r1b.verdict, r2b.verdict);
    }

    #[test]
    fn audit_log_capacity_is_bounded_with_oldest_first_eviction() {
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        let start = 10_000_u64;
        let total = MAX_AUDIT_LOG_ENTRIES + 64;

        for idx in 0..total {
            let seq = start.saturating_add(idx as u64);
            let id = format!("m{seq}");
            ch.process_message(&signed_msg(&id, Direction::Send, seq), "ts")
                .unwrap();
        }

        let log = ch.audit_log();
        assert_eq!(log.len(), MAX_AUDIT_LOG_ENTRIES);
        assert_eq!(
            log.first().map(|entry| entry.sequence_number),
            Some(start.saturating_add(64))
        );
        assert_eq!(
            log.last().map(|entry| entry.sequence_number),
            Some(start.saturating_add(total as u64 - 1))
        );
    }

    // ---------------------------------------------------------------
    // Adversarial / security tests (bd-3cvu acceptance criteria 6)
    // ---------------------------------------------------------------

    #[test]
    fn adversarial_guessed_token_injection() {
        // Attacker guesses a token with zeroed or random MAC bytes.
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        for mac_byte in [0x00, 0xFF, 0x42] {
            let cred = ChannelCredential {
                subject_id: "attacker".into(),
                epoch: ControlEpoch::new(1),
                nonce: [mac_byte; 16],
                mac: [mac_byte; SIGNATURE_LEN],
            };
            let m = ChannelMessage {
                message_id: format!("attack-{mac_byte}"),
                direction: Direction::Send,
                sequence_number: 1,
                credential: cred,
                payload_hash: "test-payload-hash".into(),
            };
            let err = ch.process_message(&m, "ts").unwrap_err();
            assert_eq!(err.code(), "ACC_AUTH_FAILED");
        }
    }

    #[test]
    fn adversarial_payload_swap_under_reused_auth() {
        // Valid credential for payload "A", but message carries payload "B".
        let cfg = config();
        let mut ch = ControlChannel::new(cfg.clone(), test_secret()).unwrap();
        let nonce = [0x01; 16];
        let cred = sign_channel_message(
            &cfg,
            "test-subject",
            Direction::Send,
            1,
            "payload-A",
            ControlEpoch::new(1),
            nonce,
            &test_secret(),
        );
        let m = ChannelMessage {
            message_id: "swap".into(),
            direction: Direction::Send,
            sequence_number: 1,
            credential: cred,
            payload_hash: "payload-B".into(), // swapped!
        };
        let err = ch.process_message(&m, "ts").unwrap_err();
        assert_eq!(err.code(), "ACC_AUTH_FAILED");
    }

    #[test]
    fn adversarial_cross_channel_replay() {
        // Credential signed for channel-A replayed on channel-B.
        let cfg_a = ChannelConfig {
            replay_window_size: 10,
            require_auth: true,
            channel_id: "channel-A".into(),
            audience: "test-audience".into(),
        };
        let nonce = [0x02; 16];
        let cred = sign_channel_message(
            &cfg_a,
            "test-subject",
            Direction::Send,
            1,
            "hash",
            ControlEpoch::new(1),
            nonce,
            &test_secret(),
        );

        let cfg_b = ChannelConfig {
            replay_window_size: 10,
            require_auth: true,
            channel_id: "channel-B".into(),
            audience: "test-audience".into(),
        };
        let mut ch_b = ControlChannel::new(cfg_b, test_secret()).unwrap();

        let m = ChannelMessage {
            message_id: "cross".into(),
            direction: Direction::Send,
            sequence_number: 1,
            credential: cred,
            payload_hash: "hash".into(),
        };
        let err = ch_b.process_message(&m, "ts").unwrap_err();
        assert_eq!(err.code(), "ACC_AUTH_FAILED");
    }

    #[test]
    fn adversarial_stale_epoch_reuse() {
        let cfg = config();
        let nonce = [0x03; 16];
        let stale_cred = sign_channel_message(
            &cfg,
            "test-subject",
            Direction::Send,
            1,
            "hash",
            ControlEpoch::new(1),
            nonce,
            &test_secret(),
        );

        // Tamper the credential's epoch to claim epoch 2 but keep the
        // MAC from epoch 1.
        let tampered = ChannelCredential {
            epoch: ControlEpoch::new(2),
            ..stale_cred
        };

        let mut ch = ControlChannel::new(cfg, test_secret()).unwrap();
        let m = ChannelMessage {
            message_id: "stale".into(),
            direction: Direction::Send,
            sequence_number: 1,
            credential: tampered,
            payload_hash: "hash".into(),
        };
        let err = ch.process_message(&m, "ts").unwrap_err();
        assert_eq!(err.code(), "ACC_AUTH_FAILED");
    }

    #[test]
    fn adversarial_wrong_direction_replay() {
        let cfg = config();
        let nonce = [0x04; 16];
        let cred = sign_channel_message(
            &cfg,
            "test-subject",
            Direction::Send,
            1,
            "hash",
            ControlEpoch::new(1),
            nonce,
            &test_secret(),
        );

        let mut ch = ControlChannel::new(cfg, test_secret()).unwrap();
        let m = ChannelMessage {
            message_id: "dir-swap".into(),
            direction: Direction::Receive, // swapped!
            sequence_number: 1,
            credential: cred,
            payload_hash: "hash".into(),
        };
        let err = ch.process_message(&m, "ts").unwrap_err();
        assert_eq!(err.code(), "ACC_AUTH_FAILED");
    }

    #[test]
    fn adversarial_wrong_secret_rejected() {
        let cfg = config();
        let other_secret = RootSecret::from_bytes([0xCD; SIGNATURE_LEN]);
        let nonce = [0x05; 16];
        let cred = sign_channel_message(
            &cfg,
            "test-subject",
            Direction::Send,
            1,
            "hash",
            ControlEpoch::new(1),
            nonce,
            &other_secret,
        );

        let mut ch = ControlChannel::new(cfg, test_secret()).unwrap();
        let m = ChannelMessage {
            message_id: "wrong-key".into(),
            direction: Direction::Send,
            sequence_number: 1,
            credential: cred,
            payload_hash: "hash".into(),
        };
        let err = ch.process_message(&m, "ts").unwrap_err();
        assert_eq!(err.code(), "ACC_AUTH_FAILED");
    }

    #[test]
    fn adversarial_sequence_number_tamper() {
        let cfg = config();
        let nonce = [0x06; 16];
        let cred = sign_channel_message(
            &cfg,
            "test-subject",
            Direction::Send,
            1,
            "hash",
            ControlEpoch::new(1),
            nonce,
            &test_secret(),
        );

        let mut ch = ControlChannel::new(cfg, test_secret()).unwrap();
        let m = ChannelMessage {
            message_id: "seq-tamper".into(),
            direction: Direction::Send,
            sequence_number: 2, // tampered!
            credential: cred,
            payload_hash: "hash".into(),
        };
        let err = ch.process_message(&m, "ts").unwrap_err();
        assert_eq!(err.code(), "ACC_AUTH_FAILED");
    }

    #[test]
    fn adversarial_nonce_reuse_within_epoch() {
        let cfg = config();
        let mut ch = ControlChannel::new(cfg.clone(), test_secret()).unwrap();
        let nonce = [0x07; 16];

        let cred1 = sign_channel_message(
            &cfg,
            "test-subject",
            Direction::Send,
            1,
            "hash",
            ControlEpoch::new(1),
            nonce,
            &test_secret(),
        );
        let m1 = ChannelMessage {
            message_id: "nonce1".into(),
            direction: Direction::Send,
            sequence_number: 1,
            credential: cred1,
            payload_hash: "hash".into(),
        };
        ch.process_message(&m1, "ts").unwrap();

        let cred2 = sign_channel_message(
            &cfg,
            "test-subject",
            Direction::Send,
            2,
            "hash2",
            ControlEpoch::new(1),
            nonce, // same nonce!
            &test_secret(),
        );
        let m2 = ChannelMessage {
            message_id: "nonce2".into(),
            direction: Direction::Send,
            sequence_number: 2,
            credential: cred2,
            payload_hash: "hash2".into(),
        };
        let err = ch.process_message(&m2, "ts").unwrap_err();
        assert_eq!(err.code(), "ACC_AUTH_FAILED");
    }

    #[test]
    fn sign_verify_round_trip() {
        let cfg = config();
        let secret = test_secret();
        let mut ch = ControlChannel::new(cfg.clone(), secret.clone()).unwrap();

        for seq in 1..=5 {
            let nonce = {
                let mut n = [0u8; 16];
                n[0] = seq as u8;
                n
            };
            let cred = sign_channel_message(
                &cfg,
                "alice",
                Direction::Send,
                seq,
                "payload",
                ControlEpoch::new(1),
                nonce,
                &secret,
            );
            let m = ChannelMessage {
                message_id: format!("rt-{seq}"),
                direction: Direction::Send,
                sequence_number: seq,
                credential: cred,
                payload_hash: "payload".into(),
            };
            ch.process_message(&m, "ts").unwrap();
        }
        assert_eq!(ch.audit_log().len(), 5);
    }

    // ---------------------------------------------------------------
    // Regression checker: ensure !token.is_empty() shortcut is gone
    // (bd-3cvu acceptance criteria 7)
    // ---------------------------------------------------------------

    #[test]
    fn regression_non_empty_string_is_not_sufficient() {
        // This test explicitly verifies that a ChannelMessage carrying
        // only a "non-empty" but cryptographically invalid credential
        // is rejected. This is the regression guard against the old
        // `!token.is_empty()` shortcut.
        let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
        let bad_cred = ChannelCredential {
            subject_id: "any-non-empty-subject".into(),
            epoch: ControlEpoch::new(1),
            nonce: [0x99; 16],
            mac: *b"this-is-32-bytes-but-not-valid!!", // 32 bytes, invalid
        };
        let m = ChannelMessage {
            message_id: "regression".into(),
            direction: Direction::Send,
            sequence_number: 1,
            credential: bad_cred,
            payload_hash: "hash".into(),
        };
        let err = ch.process_message(&m, "ts").unwrap_err();
        assert_eq!(err.code(), "ACC_AUTH_FAILED");
        // Verify the audit log captures the reason.
        assert_eq!(ch.audit_log().len(), 1);
        assert_eq!(
            ch.audit_log()[0].reason_code.as_deref(),
            Some("transcript_mac_mismatch")
        );
    }
}
