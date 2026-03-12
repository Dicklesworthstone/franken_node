//! Integration tests for bd-v97o: Authenticated control channel.

use frankenengine_node::connector::control_channel::*;
use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use frankenengine_node::security::epoch_scoped_keys::{RootSecret, SIGNATURE_LEN};

fn config() -> ChannelConfig {
    ChannelConfig {
        replay_window_size: 10,
        require_auth: true,
        channel_id: "integration-channel".into(),
        audience: "integration-audience".into(),
    }
}

fn test_secret() -> RootSecret {
    RootSecret::from_bytes([0xAB; SIGNATURE_LEN])
}

fn msg(id: &str, dir: Direction, seq: u64) -> ChannelMessage {
    let cfg = config();
    let payload_hash = format!("hash-{id}-{seq}");
    let mut nonce = [0u8; 16];
    for (idx, byte) in format!("{id}:{seq}").bytes().take(16).enumerate() {
        nonce[idx] = byte;
    }
    let credential = sign_channel_message(
        &cfg,
        "integration-subject",
        dir,
        seq,
        &payload_hash,
        ControlEpoch::new(1),
        nonce,
        &test_secret(),
    );

    ChannelMessage {
        message_id: id.into(),
        direction: dir,
        sequence_number: seq,
        credential,
        payload_hash,
    }
}

fn forged_msg(id: &str, dir: Direction, seq: u64) -> ChannelMessage {
    ChannelMessage {
        message_id: id.into(),
        direction: dir,
        sequence_number: seq,
        credential: ChannelCredential {
            subject_id: "attacker".into(),
            epoch: ControlEpoch::new(1),
            nonce: [0xFF; 16],
            mac: [0x00; SIGNATURE_LEN],
        },
        payload_hash: format!("hash-{id}-{seq}"),
    }
}

#[test]
fn inv_acc_authenticated() {
    let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
    let err = ch
        .process_message(&forged_msg("m1", Direction::Send, 1), "ts")
        .unwrap_err();
    assert_eq!(
        err.code(),
        "ACC_AUTH_FAILED",
        "INV-ACC-AUTHENTICATED: invalid credential must fail"
    );
}

#[test]
fn inv_acc_monotonic() {
    let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
    ch.process_message(&msg("m1", Direction::Send, 5), "ts")
        .unwrap();
    let err = ch
        .process_message(&msg("m2", Direction::Send, 3), "ts")
        .unwrap_err();
    assert_eq!(
        err.code(),
        "ACC_SEQUENCE_REGRESS",
        "INV-ACC-MONOTONIC: regress must be rejected"
    );
    // Different direction unaffected
    ch.process_message(&msg("m3", Direction::Receive, 1), "ts")
        .unwrap();
}

#[test]
fn inv_acc_replay_window() {
    let mut cfg = config();
    cfg.replay_window_size = 2;
    let mut ch = ControlChannel::new(cfg, test_secret()).unwrap();
    ch.process_message(&msg("m0", Direction::Send, 0), "ts")
        .unwrap();
    ch.process_message(&msg("m1", Direction::Send, 1), "ts")
        .unwrap();

    let err = ch
        .process_message(&msg("m0-replay", Direction::Send, 0), "ts")
        .unwrap_err();
    assert_eq!(
        err.code(),
        "ACC_REPLAY_DETECTED",
        "INV-ACC-REPLAY-WINDOW: zero-based replay must stay in-window"
    );
}

#[test]
fn inv_acc_auditable() {
    let mut ch = ControlChannel::new(config(), test_secret()).unwrap();
    ch.process_message(&msg("m1", Direction::Send, 1), "ts")
        .unwrap();
    let _ = ch.process_message(&forged_msg("m2", Direction::Send, 2), "ts");
    let log = ch.audit_log();
    assert_eq!(log.len(), 2, "INV-ACC-AUDITABLE: all checks must be logged");
    assert!(log.iter().any(|e| e.verdict == "ACCEPT"));
    assert!(log.iter().any(|e| e.verdict == "REJECT_AUTH"));
}
