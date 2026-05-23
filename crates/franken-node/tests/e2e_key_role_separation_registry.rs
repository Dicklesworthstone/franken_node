//! Mock-free end-to-end test for the control-plane key role separation registry.
//!
//! Drives `frankenengine_node::control_plane::key_role_separation::KeyRoleRegistry`
//! through every public-API path:
//!
//!   1. `bind` happy path for each `KeyRole` variant,
//!   2. `bind` idempotent re-bind (same key_id, same role, same material),
//!   3. `bind` with same key_id + same role + DIFFERENT material →
//!      `KeyMaterialMismatch`,
//!   4. `bind` with same key_id + DIFFERENT role →
//!      `RoleSeparationViolation` (INV-KRS-ROLE-EXCLUSIVITY),
//!   5. `revoke` happy path moves binding to revoked set,
//!   6. `revoke` of unknown key → `KeyNotFound`,
//!   7. `rotate` atomic happy path: old key revoked, new key bound
//!      (INV-KRS-ROTATION-ATOMIC),
//!   8. `rotate` with old==new → `RotationFailed`,
//!   9. `rotate` when old key has different role → `RotationFailed`,
//!  10. `verify_role` success + KeyRoleMismatch + KeyExpired
//!      (INV-KRS-ROLE-GUARD), all fail-closed at the boundary,
//!  11. `KeyRole::tag` / `from_tag` round-trip for every variant +
//!      unknown tag returns `None`,
//!  12. `lookup_by_role` returns only bindings of that role.
//!
//! Bead: bd-3sbyp.
//!
//! No mocks: real `KeyRoleRegistry`, real BTreeMap-backed bindings,
//! real constant-time public-key comparison. Each phase emits a
//! structured tracing event PLUS a JSON-line on stderr.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::control_plane::key_role_separation::{
    KeyRole, KeyRoleRegistry, KeyRoleSeparationError, event_codes,
};
use serde_json::json;
use tracing::{error, info};

static TEST_TRACING_INIT: Once = Once::new();

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

#[derive(serde::Serialize)]
struct PhaseLog<'a> {
    timestamp: String,
    test_name: &'a str,
    phase: &'a str,
    duration_ms: u64,
    success: bool,
    detail: serde_json::Value,
}

struct Harness {
    test_name: &'static str,
    started: Instant,
}

impl Harness {
    fn new(test_name: &'static str) -> Self {
        init_test_tracing();
        let h = Self {
            test_name,
            started: Instant::now(),
        };
        h.log_phase("setup", true, json!({}));
        h
    }

    fn log_phase(&self, phase: &str, success: bool, detail: serde_json::Value) {
        let entry = PhaseLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: self.test_name,
            phase,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            success,
            detail,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&entry).expect("phase log serializes")
        );
        if success {
            info!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase completed"
            );
        } else {
            error!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase failed"
            );
        }
    }
}

const AUTHORITY: &str = "operator-prod-1";
const NOW: u64 = 1_745_750_000;
const VALIDITY: u64 = 86_400; // 24h

#[test]
fn e2e_key_role_separation_bind_and_role_exclusivity() {
    let h = Harness::new("e2e_key_role_separation_bind_and_role_exclusivity");

    let mut reg = KeyRoleRegistry::new();
    assert_eq!(reg.active_count(), 0);
    assert_eq!(reg.revoked_count(), 0);

    // Bind one of every role.
    for (i, role) in KeyRole::all().iter().enumerate() {
        let key_id = format!("key-{i:02}");
        reg.bind(
            &key_id,
            *role,
            vec![i as u8; 32],
            AUTHORITY,
            NOW,
            VALIDITY,
            &format!("trace-bind-{i}"),
        )
        .expect("bind ok");
    }
    assert_eq!(reg.active_count(), 4);
    h.log_phase("all_roles_bound", true, json!({"active": 4}));

    // INV-KRS-ROLE-EXCLUSIVITY: re-binding the same key_id to a DIFFERENT
    // role is rejected with RoleSeparationViolation.
    let err = reg
        .bind(
            "key-00", // already bound to Signing
            KeyRole::Encryption,
            vec![0xAA; 32],
            AUTHORITY,
            NOW,
            VALIDITY,
            "trace-violation",
        )
        .expect_err("role separation violation rejected");
    match err {
        KeyRoleSeparationError::RoleSeparationViolation {
            existing_role,
            attempted_role,
            ..
        } => {
            assert_eq!(existing_role, KeyRole::Signing);
            assert_eq!(attempted_role, KeyRole::Encryption);
            assert_eq!(err.code(), "KRS_ROLE_SEPARATION_VIOLATION");
            h.log_phase(
                "role_exclusivity_enforced",
                true,
                json!({"code": err.code()}),
            );
        }
        other => panic!("expected RoleSeparationViolation, got {other:?}"),
    }
    assert_eq!(reg.active_count(), 4);

    // Idempotent re-bind: same key_id + same role + same material → ok.
    reg.bind(
        "key-00",
        KeyRole::Signing,
        vec![0u8; 32], // same material as initial bind
        AUTHORITY,
        NOW,
        VALIDITY,
        "trace-idempotent",
    )
    .expect("idempotent re-bind ok");
    assert_eq!(reg.active_count(), 4);
    h.log_phase("idempotent_rebind", true, json!({}));

    // Same key_id + same role + DIFFERENT material → KeyMaterialMismatch.
    let err = reg
        .bind(
            "key-00",
            KeyRole::Signing,
            vec![0xFF; 32], // different material
            AUTHORITY,
            NOW,
            VALIDITY,
            "trace-material",
        )
        .expect_err("material mismatch rejected");
    match err {
        KeyRoleSeparationError::KeyMaterialMismatch { .. } => {
            assert_eq!(err.code(), "KRS_KEY_MATERIAL_MISMATCH");
            h.log_phase(
                "material_mismatch_rejected",
                true,
                json!({"code": err.code()}),
            );
        }
        other => panic!("expected KeyMaterialMismatch, got {other:?}"),
    }

    // lookup_by_role returns exactly the bindings for that role.
    let signing = reg.lookup_by_role(KeyRole::Signing);
    assert_eq!(signing.len(), 1);
    assert_eq!(signing[0].key_id, "key-00");
    let encryption = reg.lookup_by_role(KeyRole::Encryption);
    assert_eq!(encryption.len(), 1);
    assert_eq!(encryption[0].key_id, "key-01");
    h.log_phase(
        "lookup_by_role",
        true,
        json!({"signing": 1, "encryption": 1}),
    );
}

#[test]
fn e2e_key_role_separation_revoke() {
    let h = Harness::new("e2e_key_role_separation_revoke");

    let mut reg = KeyRoleRegistry::new();
    reg.bind(
        "key-revoke-1",
        KeyRole::Issuance,
        vec![0xCC; 32],
        AUTHORITY,
        NOW,
        VALIDITY,
        "trace-bind",
    )
    .expect("bind ok");
    assert_eq!(reg.active_count(), 1);

    let revoked = reg
        .revoke("key-revoke-1", AUTHORITY, "trace-revoke")
        .expect("revoke ok");
    assert_eq!(revoked.role, KeyRole::Issuance);
    assert_eq!(reg.active_count(), 0);
    assert_eq!(reg.revoked_count(), 1);
    assert!(reg.lookup("key-revoke-1").is_none());
    h.log_phase("revoked", true, json!({"revoked_count": 1}));

    // Revoking unknown key → KeyNotFound.
    let err = reg
        .revoke("key-ghost", AUTHORITY, "trace-ghost")
        .expect_err("unknown key rejected");
    assert!(matches!(err, KeyRoleSeparationError::KeyNotFound { .. }));
    assert_eq!(err.code(), "KRS_KEY_NOT_FOUND");
    h.log_phase("unknown_key_rejected", true, json!({"code": err.code()}));
}

#[test]
fn e2e_key_role_separation_rotate_atomic() {
    let h = Harness::new("e2e_key_role_separation_rotate_atomic");

    let mut reg = KeyRoleRegistry::new();
    reg.bind(
        "key-old",
        KeyRole::Attestation,
        vec![0x10; 32],
        AUTHORITY,
        NOW,
        VALIDITY,
        "trace-old-bind",
    )
    .expect("bind old");

    // Same key_id rejected.
    let err = reg
        .rotate(
            KeyRole::Attestation,
            "key-old",
            "key-old",
            vec![0x20; 32],
            AUTHORITY,
            NOW + 100,
            VALIDITY,
            "trace-rotate-same",
        )
        .expect_err("same-key rotation rejected");
    assert!(matches!(err, KeyRoleSeparationError::RotationFailed { .. }));
    h.log_phase("same_key_rotation_rejected", true, json!({}));

    // Wrong role for old_key rejected.
    let err = reg
        .rotate(
            KeyRole::Signing, // old key is Attestation, not Signing
            "key-old",
            "key-new",
            vec![0x20; 32],
            AUTHORITY,
            NOW + 100,
            VALIDITY,
            "trace-rotate-wrong-role",
        )
        .expect_err("wrong-role rotation rejected");
    assert!(matches!(err, KeyRoleSeparationError::RotationFailed { .. }));
    h.log_phase("wrong_role_rotation_rejected", true, json!({}));

    // Atomic rotation succeeds: old revoked, new bound.
    let new_binding = reg
        .rotate(
            KeyRole::Attestation,
            "key-old",
            "key-new",
            vec![0x20; 32],
            AUTHORITY,
            NOW + 100,
            VALIDITY,
            "trace-rotate-ok",
        )
        .expect("rotate ok");
    assert_eq!(new_binding.key_id, "key-new");
    assert_eq!(new_binding.role, KeyRole::Attestation);
    assert!(reg.lookup("key-old").is_none(), "old key removed");
    assert!(reg.lookup("key-new").is_some(), "new key active");
    assert_eq!(reg.active_count(), 1);
    assert_eq!(reg.revoked_count(), 1, "old binding moved to revoked");
    h.log_phase(
        "rotate_atomic",
        true,
        json!({"new_key_id": "key-new", "active": 1, "revoked": 1}),
    );
}

#[test]
fn e2e_key_role_rotation_order_is_stable_across_composed_handoffs()
-> Result<(), KeyRoleSeparationError> {
    let h = Harness::new("e2e_key_role_rotation_order_is_stable_across_composed_handoffs");

    let mut reg = KeyRoleRegistry::new();
    reg.bind(
        "key-order-old",
        KeyRole::Attestation,
        vec![0x10; 32],
        AUTHORITY,
        NOW,
        VALIDITY,
        "trace-order-bind",
    )?;

    reg.rotate(
        KeyRole::Attestation,
        "key-order-old",
        "key-order-mid",
        vec![0x20; 32],
        AUTHORITY,
        NOW + 100,
        VALIDITY,
        "trace-order-rotate-mid",
    )?;
    reg.rotate(
        KeyRole::Attestation,
        "key-order-mid",
        "key-order-new",
        vec![0x30; 32],
        AUTHORITY,
        NOW + 200,
        VALIDITY,
        "trace-order-rotate-new",
    )?;

    assert!(reg.lookup("key-order-old").is_none());
    assert!(reg.lookup("key-order-mid").is_none());
    let expected_final_key = [0x30; 32];
    assert_eq!(
        reg.lookup("key-order-new").map(|binding| binding.role),
        Some(KeyRole::Attestation)
    );
    assert_eq!(
        reg.lookup("key-order-new")
            .map(|binding| binding.public_key_bytes.as_slice()),
        Some(expected_final_key.as_slice())
    );
    assert_eq!(reg.active_count(), 1);
    assert_eq!(reg.revoked_count(), 2);
    assert_eq!(
        reg.revoked_bindings()
            .iter()
            .map(|binding| binding.key_id.as_str())
            .collect::<Vec<_>>(),
        vec!["key-order-old", "key-order-mid"],
        "MUST preserve composed rotation handoff order in the revoked audit trail"
    );
    assert_eq!(
        reg.events()
            .iter()
            .map(|event| event.event_code.as_str())
            .collect::<Vec<_>>(),
        vec![
            event_codes::KRS_KEY_ROLE_BOUND,
            event_codes::KRS_KEY_ROLE_ROTATED,
            event_codes::KRS_KEY_ROLE_ROTATED,
        ],
        "SHOULD emit deterministic event order for composed rotations"
    );
    h.log_phase(
        "composed_rotation_order_stable",
        true,
        json!({
            "active": reg.active_count(),
            "revoked": reg.revoked_count(),
            "final_key": "key-order-new",
        }),
    );
    Ok(())
}

#[test]
fn e2e_key_role_separation_verify_role_guard() {
    let h = Harness::new("e2e_key_role_separation_verify_role_guard");

    let mut reg = KeyRoleRegistry::new();
    reg.bind(
        "key-guard-1",
        KeyRole::Signing,
        vec![0xAB; 32],
        AUTHORITY,
        NOW,
        VALIDITY,
        "trace-bind",
    )
    .expect("bind ok");

    // Within validity window + correct role → ok.
    reg.verify_role("key-guard-1", KeyRole::Signing, NOW + 1, "trace-ok")
        .expect("verify ok within window");
    h.log_phase("within_window_ok", true, json!({}));

    // Wrong expected role → KeyRoleMismatch.
    let err = reg
        .verify_role(
            "key-guard-1",
            KeyRole::Encryption,
            NOW + 1,
            "trace-mismatch",
        )
        .expect_err("wrong role rejected");
    match err {
        KeyRoleSeparationError::KeyRoleMismatch {
            expected_role,
            actual_role,
            ..
        } => {
            assert_eq!(expected_role, KeyRole::Encryption);
            assert_eq!(actual_role, KeyRole::Signing);
            assert_eq!(err.code(), "KRS_KEY_ROLE_MISMATCH");
            h.log_phase("role_mismatch", true, json!({"code": err.code()}));
        }
        other => panic!("expected KeyRoleMismatch, got {other:?}"),
    }

    // Boundary: now == bound_at + max_validity → KeyExpired (fail-closed `>=`).
    let err = reg
        .verify_role(
            "key-guard-1",
            KeyRole::Signing,
            NOW + VALIDITY,
            "trace-boundary",
        )
        .expect_err("expiry boundary fail-closed");
    assert!(matches!(err, KeyRoleSeparationError::KeyExpired { .. }));
    assert_eq!(err.code(), "KRS_KEY_EXPIRED");
    h.log_phase(
        "expired_boundary_fail_closed",
        true,
        json!({"code": err.code()}),
    );

    // Past boundary → still expired.
    let err = reg
        .verify_role(
            "key-guard-1",
            KeyRole::Signing,
            NOW + VALIDITY + 1000,
            "trace-past",
        )
        .expect_err("expired past boundary");
    assert!(matches!(err, KeyRoleSeparationError::KeyExpired { .. }));

    // Unknown key → KeyNotFound (in verify_role too, not just revoke).
    let err = reg
        .verify_role("key-ghost", KeyRole::Signing, NOW + 1, "trace-ghost")
        .expect_err("unknown rejected");
    assert!(matches!(err, KeyRoleSeparationError::KeyNotFound { .. }));
    h.log_phase("unknown_in_verify", true, json!({}));
}

#[test]
fn e2e_key_role_tag_round_trip() {
    let h = Harness::new("e2e_key_role_tag_round_trip");

    // Every variant: tag → from_tag → identity.
    for role in KeyRole::all() {
        let tag = role.tag();
        let parsed = KeyRole::from_tag(tag).expect("from_tag round-trips");
        assert_eq!(parsed, *role);
        // tag_u16 is the big-endian u16 of the tag bytes.
        assert_eq!(role.tag_u16(), u16::from_be_bytes(tag));
    }
    h.log_phase("all_tags_round_trip", true, json!({}));

    // Unknown tag → None.
    assert!(KeyRole::from_tag([0xFF, 0xFF]).is_none());
    assert!(KeyRole::from_tag([0x00, 0x00]).is_none());
    h.log_phase("unknown_tag_none", true, json!({}));
}
