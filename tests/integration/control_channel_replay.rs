//! Integration tests for bd-v97o: Authenticated control channel.

use frankenengine_node::connector::control_channel::*;

fn config() -> ChannelConfig {
    ChannelConfig { replay_window_size: 10, require_auth: true }
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
fn inv_acc_authenticated() {
    let mut ch = ControlChannel::new(config()).unwrap();
    let err = ch.process_message(&msg("m1", Direction::Send, 1, ""), "ts").unwrap_err();
    assert_eq!(err.code(), "ACC_AUTH_FAILED", "INV-ACC-AUTHENTICATED: empty token must fail");
}

#[test]
fn inv_acc_monotonic() {
    let mut ch = ControlChannel::new(config()).unwrap();
    ch.process_message(&msg("m1", Direction::Send, 5, "tok"), "ts").unwrap();
    let err = ch.process_message(&msg("m2", Direction::Send, 3, "tok"), "ts").unwrap_err();
    assert_eq!(err.code(), "ACC_SEQUENCE_REGRESS", "INV-ACC-MONOTONIC: regress must be rejected");
    // Different direction unaffected
    ch.process_message(&msg("m3", Direction::Receive, 1, "tok"), "ts").unwrap();
}

#[test]
fn inv_acc_replay_window() {
    let mut ch = ControlChannel::new(config()).unwrap();
    ch.process_message(&msg("m1", Direction::Send, 1, "tok"), "ts").unwrap();
    // Trying seq 1 again should fail (either as regress or replay)
    let err = ch.process_message(&msg("m2", Direction::Send, 1, "tok"), "ts").unwrap_err();
    let code = err.code();
    assert!(code == "ACC_SEQUENCE_REGRESS" || code == "ACC_REPLAY_DETECTED",
        "INV-ACC-REPLAY-WINDOW: replay must be detected, got {code}");
}

#[test]
fn inv_acc_auditable() {
    let mut ch = ControlChannel::new(config()).unwrap();
    ch.process_message(&msg("m1", Direction::Send, 1, "tok"), "ts").unwrap();
    let _ = ch.process_message(&msg("m2", Direction::Send, 2, ""), "ts"); // auth fail
    let log = ch.audit_log();
    assert_eq!(log.len(), 2, "INV-ACC-AUDITABLE: all checks must be logged");
    assert!(log.iter().any(|e| e.verdict == "ACCEPT"));
    assert!(log.iter().any(|e| e.verdict == "REJECT_AUTH"));
}
