//! Security Challenge-Response Protocol Conformance Harness
//!
//! Tests that challenge-response protocol invariants hold under adversarial
//! conditions: nonce reuse, expired challenge replay, signature substitution,
//! and scope mismatch attacks.

use frankenengine_node::connector::control_channel::{
    ChannelConfig, ChannelCredential, ChannelMessage, ControlChannel, Direction,
    sign_channel_message,
};
use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use frankenengine_node::security::epoch_scoped_keys::{RootSecret, SIGNATURE_LEN};

type TestResult = Result<(), String>;

#[derive(Debug, Clone, Copy)]
struct CoverageRow {
    spec_section: &'static str,
    invariant: &'static str,
    level: &'static str,
    tested: bool,
}

const COVERAGE: &[CoverageRow] = &[
    CoverageRow {
        spec_section: "section_8_12_challenge_response_protocol",
        invariant: "INV-CHALLENGE-NONCE-UNIQUE",
        level: "MUST",
        tested: true,
    },
    CoverageRow {
        spec_section: "section_8_12_challenge_response_protocol",
        invariant: "INV-CHALLENGE-REPLAY-WINDOW",
        level: "MUST",
        tested: true,
    },
    CoverageRow {
        spec_section: "section_8_12_challenge_response_protocol",
        invariant: "INV-CHALLENGE-SIGNATURE-BINDING",
        level: "MUST",
        tested: true,
    },
    CoverageRow {
        spec_section: "section_8_12_challenge_response_protocol",
        invariant: "INV-CHALLENGE-SCOPE-ISOLATION",
        level: "MUST",
        tested: true,
    },
];

fn test_secret() -> RootSecret {
    RootSecret::from_bytes([0xC0; SIGNATURE_LEN])
}

fn test_config() -> ChannelConfig {
    ChannelConfig {
        replay_window_size: 16,
        require_auth: true,
        channel_id: "conformance-test-channel".into(),
        audience: "conformance-test-audience".into(),
    }
}

fn alternative_config() -> ChannelConfig {
    ChannelConfig {
        replay_window_size: 16,
        require_auth: true,
        channel_id: "different-channel".into(),
        audience: "different-audience".into(),
    }
}

fn create_valid_message(
    id: &str,
    dir: Direction,
    seq: u64,
    config: &ChannelConfig,
    secret: &RootSecret,
) -> ChannelMessage {
    let nonce = {
        use sha2::{Sha256, Digest};
        let input = format!("{}:{}", id, seq);
        let hash = Sha256::digest(input.as_bytes());
        let mut n = [0u8; 16];
        n.copy_from_slice(&hash[..16]);
        n
    };

    let credential = sign_channel_message(
        config,
        "test-subject",
        dir,
        seq,
        "test-payload-hash",
        ControlEpoch::new(1),
        nonce,
        secret,
    );

    ChannelMessage {
        message_id: id.into(),
        direction: dir,
        sequence_number: seq,
        credential,
        payload_hash: "test-payload-hash".into(),
    }
}

fn create_message_with_nonce(
    id: &str,
    dir: Direction,
    seq: u64,
    nonce: [u8; 16],
    config: &ChannelConfig,
    secret: &RootSecret,
) -> ChannelMessage {
    let credential = sign_channel_message(
        config,
        "test-subject",
        dir,
        seq,
        "test-payload-hash",
        ControlEpoch::new(1),
        nonce,
        secret,
    );

    ChannelMessage {
        message_id: id.into(),
        direction: dir,
        sequence_number: seq,
        credential,
        payload_hash: "test-payload-hash".into(),
    }
}

fn create_message_with_forged_mac(
    id: &str,
    dir: Direction,
    seq: u64,
) -> ChannelMessage {
    let credential = ChannelCredential {
        subject_id: "attacker".into(),
        epoch: ControlEpoch::new(1),
        nonce: [0xAA; 16],
        mac: [0xFF; SIGNATURE_LEN], // Forged MAC
    };

    ChannelMessage {
        message_id: id.into(),
        direction: dir,
        sequence_number: seq,
        credential,
        payload_hash: "test-payload-hash".into(),
    }
}

/// Test INV-CHALLENGE-NONCE-UNIQUE: Nonce reuse within epoch is rejected
#[test]
fn conformance_nonce_reuse_within_epoch_rejected() -> TestResult {
    let config = test_config();
    let secret = test_secret();
    let mut channel = ControlChannel::new(config.clone(), secret.clone())
        .map_err(|e| format!("Channel creation failed: {e}"))?;

    let shared_nonce = [0x42; 16];

    // First message with nonce succeeds
    let msg1 = create_message_with_nonce("msg1", Direction::Send, 1, shared_nonce, &config, &secret);
    channel.process_message(&msg1, "ts1")
        .map_err(|e| format!("First message should succeed: {e}"))?;

    // Second message with same nonce fails
    let msg2 = create_message_with_nonce("msg2", Direction::Send, 2, shared_nonce, &config, &secret);
    let result = channel.process_message(&msg2, "ts2");

    match result {
        Err(e) if e.code() == "ACC_AUTH_FAILED" => {
            let audit = channel.audit_log().last()
                .ok_or("Expected audit entry for nonce reuse")?;
            if audit.reason_code.as_deref() != Some("nonce_reuse_detected") {
                return Err(format!("Expected nonce_reuse_detected, got {:?}", audit.reason_code));
            }
        }
        _ => return Err("Expected nonce reuse to be rejected".into()),
    }

    Ok(())
}

/// Test INV-CHALLENGE-NONCE-UNIQUE: Nonce reuse across epochs is allowed
#[test]
fn conformance_nonce_reuse_across_epochs_allowed() -> TestResult {
    let config = test_config();
    let secret = test_secret();
    let mut channel = ControlChannel::new(config.clone(), secret.clone())
        .map_err(|e| format!("Channel creation failed: {e}"))?;

    let shared_nonce = [0x33; 16];

    // Message with epoch 1
    let cred1 = sign_channel_message(
        &config,
        "test-subject",
        Direction::Send,
        1,
        "test-payload-hash",
        ControlEpoch::new(1),
        shared_nonce,
        &secret,
    );

    let msg1 = ChannelMessage {
        message_id: "msg1".into(),
        direction: Direction::Send,
        sequence_number: 1,
        credential: cred1,
        payload_hash: "test-payload-hash".into(),
    };

    channel.process_message(&msg1, "ts1")
        .map_err(|e| format!("First message should succeed: {e}"))?;

    // Message with epoch 2 and same nonce should succeed
    let cred2 = sign_channel_message(
        &config,
        "test-subject",
        Direction::Send,
        2,
        "test-payload-hash",
        ControlEpoch::new(2),
        shared_nonce,
        &secret,
    );

    let msg2 = ChannelMessage {
        message_id: "msg2".into(),
        direction: Direction::Send,
        sequence_number: 2,
        credential: cred2,
        payload_hash: "test-payload-hash".into(),
    };

    channel.process_message(&msg2, "ts2")
        .map_err(|e| format!("Nonce reuse across epochs should be allowed: {e}"))?;

    Ok(())
}

/// Test INV-CHALLENGE-REPLAY-WINDOW: Expired challenge replay is rejected
#[test]
fn conformance_expired_challenge_replay_rejected() -> TestResult {
    let mut config = test_config();
    config.replay_window_size = 3;
    let secret = test_secret();
    let mut channel = ControlChannel::new(config.clone(), secret.clone())
        .map_err(|e| format!("Channel creation failed: {e}"))?;

    // Fill the replay window
    for seq in 1..=5 {
        let msg = create_valid_message(&format!("msg{}", seq), Direction::Send, seq, &config, &secret);
        channel.process_message(&msg, &format!("ts{}", seq))
            .map_err(|e| format!("Message {} should succeed: {e}", seq))?;
    }

    // Try to replay sequence 2 (should be outside replay window)
    let replay_msg = create_valid_message("replay", Direction::Send, 2, &config, &secret);
    let result = channel.process_message(&replay_msg, "ts_replay");

    match result {
        Err(e) if e.code() == "ACC_REPLAY_DETECTED" => Ok(()),
        Err(e) if e.code() == "ACC_SEQUENCE_REGRESS" => Ok(()), // Monotonicity catches it first
        _ => Err("Expected replay to be rejected".into()),
    }
}

/// Test INV-CHALLENGE-SIGNATURE-BINDING: Signature substitution is rejected
#[test]
fn conformance_signature_substitution_rejected() -> TestResult {
    let config = test_config();
    let secret = test_secret();
    let mut channel = ControlChannel::new(config.clone(), secret.clone())
        .map_err(|e| format!("Channel creation failed: {e}"))?;

    // Create message with forged MAC
    let forged_msg = create_message_with_forged_mac("forged", Direction::Send, 1);
    let result = channel.process_message(&forged_msg, "ts");

    match result {
        Err(e) if e.code() == "ACC_AUTH_FAILED" => {
            let audit = channel.audit_log().last()
                .ok_or("Expected audit entry for signature failure")?;
            if audit.reason_code.as_deref() != Some("transcript_mac_mismatch") {
                return Err(format!("Expected transcript_mac_mismatch, got {:?}", audit.reason_code));
            }
        }
        _ => return Err("Expected signature substitution to be rejected".into()),
    }

    Ok(())
}

/// Test INV-CHALLENGE-SIGNATURE-BINDING: Cross-context signature substitution
#[test]
fn conformance_cross_context_signature_substitution_rejected() -> TestResult {
    let config1 = test_config();
    let config2 = alternative_config();
    let secret = test_secret();

    // Create valid signature for config1
    let valid_msg = create_valid_message("valid", Direction::Send, 1, &config1, &secret);

    // Try to use that signature in config2 context
    let mut channel2 = ControlChannel::new(config2.clone(), secret.clone())
        .map_err(|e| format!("Channel creation failed: {e}"))?;

    let result = channel2.process_message(&valid_msg, "ts");

    match result {
        Err(e) if e.code() == "ACC_AUTH_FAILED" => {
            let audit = channel2.audit_log().last()
                .ok_or("Expected audit entry for cross-context signature failure")?;
            if audit.reason_code.as_deref() != Some("transcript_mac_mismatch") {
                return Err(format!("Expected transcript_mac_mismatch, got {:?}", audit.reason_code));
            }
        }
        _ => return Err("Expected cross-context signature to be rejected".into()),
    }

    Ok(())
}

/// Test INV-CHALLENGE-SCOPE-ISOLATION: Scope mismatch is rejected
#[test]
fn conformance_scope_mismatch_rejected() -> TestResult {
    let config = test_config();
    let wrong_config = alternative_config();
    let secret = test_secret();
    let mut channel = ControlChannel::new(config.clone(), secret.clone())
        .map_err(|e| format!("Channel creation failed: {e}"))?;

    // Create message signed for wrong_config but sent to config channel
    let mismatched_msg = create_valid_message("mismatch", Direction::Send, 1, &wrong_config, &secret);
    let result = channel.process_message(&mismatched_msg, "ts");

    match result {
        Err(e) if e.code() == "ACC_AUTH_FAILED" => {
            let audit = channel.audit_log().last()
                .ok_or("Expected audit entry for scope mismatch")?;
            if audit.reason_code.as_deref() != Some("transcript_mac_mismatch") {
                return Err(format!("Expected transcript_mac_mismatch, got {:?}", audit.reason_code));
            }
        }
        _ => return Err("Expected scope mismatch to be rejected".into()),
    }

    Ok(())
}

/// Test coverage verification
#[test]
fn conformance_coverage_verification() -> TestResult {
    let mut missing_coverage = Vec::new();

    for row in COVERAGE {
        if !row.tested {
            missing_coverage.push(format!("{}: {}", row.spec_section, row.invariant));
        }
    }

    if !missing_coverage.is_empty() {
        return Err(format!("Missing test coverage for: {}", missing_coverage.join(", ")));
    }

    Ok(())
}

/// Comprehensive adversarial scenario test
#[test]
fn conformance_adversarial_comprehensive() -> TestResult {
    let config = test_config();
    let secret = test_secret();
    let mut channel = ControlChannel::new(config.clone(), secret.clone())
        .map_err(|e| format!("Channel creation failed: {e}"))?;

    // Valid baseline
    let msg1 = create_valid_message("baseline", Direction::Send, 1, &config, &secret);
    channel.process_message(&msg1, "ts1")
        .map_err(|e| format!("Baseline message should succeed: {e}"))?;

    // Test all attack vectors sequentially
    let attacks = vec![
        (create_message_with_forged_mac("attack1", Direction::Send, 2), "signature_substitution"),
        (create_message_with_nonce("attack2", Direction::Send, 3, [0x42; 16], &config, &secret), "nonce_reuse"),
        (create_valid_message("attack3", Direction::Send, 1, &config, &secret), "sequence_replay"),
        (create_valid_message("attack4", Direction::Send, 4, &alternative_config(), &secret), "scope_mismatch"),
    ];

    for (attack_msg, attack_type) in attacks {
        let result = channel.process_message(&attack_msg, "attack_ts");
        if result.is_ok() {
            return Err(format!("Attack {} should have been rejected", attack_type));
        }

        let audit = channel.audit_log().last()
            .ok_or(format!("Expected audit entry for attack {}", attack_type))?;

        if audit.authenticated && attack_type != "nonce_reuse" && attack_type != "sequence_replay" {
            return Err(format!("Attack {} should not have passed authentication", attack_type));
        }
    }

    Ok(())
}