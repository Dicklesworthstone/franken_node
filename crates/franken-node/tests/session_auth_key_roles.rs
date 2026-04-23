use frankenengine_node::api::session_auth::{
    sign_handshake, SessionConfig, SessionError, SessionManager,
};
use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use frankenengine_node::control_plane::key_role_separation::{KeyRole, KeyRoleRegistry};
use frankenengine_node::security::epoch_scoped_keys::RootSecret;

fn root_secret() -> RootSecret {
    RootSecret::from_bytes([0x5A; 32])
}

fn epoch() -> ControlEpoch {
    ControlEpoch::from(17_u64)
}

fn config() -> SessionConfig {
    SessionConfig {
        replay_window: 0,
        max_sessions: 8,
        session_timeout_ms: 60_000,
    }
}

fn key_material(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn key_registry() -> KeyRoleRegistry {
    let mut registry = KeyRoleRegistry::new();
    registry
        .bind(
            "enc-key",
            KeyRole::Encryption,
            key_material(1),
            "test-authority",
            0,
            10_000,
            "trace-bind-enc",
        )
        .expect("bind encryption key");
    registry
        .bind(
            "sign-key",
            KeyRole::Signing,
            key_material(2),
            "test-authority",
            0,
            10_000,
            "trace-bind-sign",
        )
        .expect("bind signing key");
    registry
        .bind(
            "issue-key",
            KeyRole::Issuance,
            key_material(3),
            "test-authority",
            0,
            10_000,
            "trace-bind-issue",
        )
        .expect("bind issuance key");
    registry
}

fn manager() -> SessionManager {
    SessionManager::with_key_role_registry(config(), root_secret(), epoch(), key_registry())
}

fn establish_with_keys(
    manager: &mut SessionManager,
    session_id: &str,
    encryption_key_id: &str,
    signing_key_id: &str,
) -> Result<(), SessionError> {
    let timestamp = 100;
    let mac = sign_handshake(
        session_id,
        "client-a",
        "server-a",
        encryption_key_id,
        signing_key_id,
        epoch(),
        timestamp,
        &root_secret(),
    );

    manager
        .establish_session(
            session_id.to_string(),
            "client-a".to_string(),
            "server-a".to_string(),
            encryption_key_id.to_string(),
            signing_key_id.to_string(),
            timestamp,
            format!("trace-{session_id}"),
            mac,
        )
        .map(|_| ())
}

#[test]
fn session_establishment_enforces_authoritative_key_roles() {
    let mut valid_manager = manager();
    establish_with_keys(&mut valid_manager, "session-valid", "enc-key", "sign-key")
        .expect("correctly bound encryption/signing keys should establish a session");

    let mut swapped_manager = manager();
    let swapped = establish_with_keys(
        &mut swapped_manager,
        "session-swapped",
        "sign-key",
        "enc-key",
    )
    .expect_err("swapped key roles must be rejected even with a valid handshake MAC");
    assert!(matches!(
        swapped,
        SessionError::RoleMismatch {
            ref expected_role,
            ref actual_role,
            ..
        } if expected_role == "Encryption" && actual_role == "Signing"
    ));

    let mut issuance_manager = manager();
    let issuance_as_signing = establish_with_keys(
        &mut issuance_manager,
        "session-issuance",
        "enc-key",
        "issue-key",
    )
    .expect_err("issuance keys must not satisfy the signing-key role");
    assert!(matches!(
        issuance_as_signing,
        SessionError::RoleMismatch {
            ref expected_role,
            ref actual_role,
            ..
        } if expected_role == "Signing" && actual_role == "Issuance"
    ));
}
