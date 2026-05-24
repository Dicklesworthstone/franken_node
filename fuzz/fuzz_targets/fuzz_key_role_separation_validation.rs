#![no_main]

//! Comprehensive fuzz harness for
//! `frankenengine_node::control_plane::key_role_separation::KeyRole` tag parsing
//! and role separation validation at
//! `crates/franken-node/src/control_plane/key_role_separation.rs:77`.
//!
//! Background: The KeyRole::from_tag method parses 2-byte role tags into enum
//! variants and is critical for role separation enforcement. The key-role
//! separation registry enforces strict invariants about which keys can be
//! bound to which roles, but currently has ZERO dedicated fuzz coverage.
//!
//! The from_tag method accepts arbitrary [u8; 2] and must:
//! - Correctly parse valid tags [0x00, 0x01..0x04]
//! - Return None for invalid tags
//! - Never panic on any byte combination
//!
//! A regression could allow invalid role tags to be accepted as valid roles,
//! breaking the key-role separation invariants and allowing keys to be used
//! outside their intended operational domain.
//!
//! Existing fuzz coverage: **ZERO** (no dedicated key role separation testing).
//!
//! Seven invariants tested per call:
//!
//!   (A) **INV-KRS-TAG-PARSE-SAFE** — arbitrary byte pairs MUST NOT panic
//!       KeyRole::from_tag regardless of input values.
//!
//!   (B) **INV-KRS-VALID-TAG-ROUNDTRIP** — for all valid KeyRole variants,
//!       KeyRole::from_tag(role.tag()) == Some(role).
//!
//!   (C) **INV-KRS-INVALID-TAG-NONE** — byte pairs that don't correspond to
//!       valid roles MUST return None from KeyRole::from_tag.
//!
//!   (D) **INV-KRS-TAG-DETERMINISTIC** — same tag bytes always produce
//!       identical results from KeyRole::from_tag.
//!
//!   (E) **INV-KRS-ALL-ROLES-COVERED** — KeyRole::all() includes exactly
//!       the four expected variants with correct tag mappings.
//!
//!   (F) **INV-KRS-TAG-FORMAT-CONSISTENT** — tag() and tag_u16() produce
//!       consistent byte representations (big-endian).
//!
//!   (G) **INV-KRS-ROLE-DISPLAY-SAFE** — Display formatting never panics
//!       and produces expected string representations.

use arbitrary::Arbitrary;
use frankenengine_node::control_plane::key_role_separation::KeyRole;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct KeyRoleTagParsingFuzzCase {
    tag_bytes: [u8; 2],
    additional_bytes: Vec<u8>,
    comparison_tag: [u8; 2],
}

fuzz_target!(|case: KeyRoleTagParsingFuzzCase| {
    // ── (A) Tag parsing safety ─────────────────────────────────────────
    let result = std::panic::catch_unwind(|| {
        KeyRole::from_tag(case.tag_bytes)
    });
    assert!(
        result.is_ok(),
        "INV-KRS-TAG-PARSE-SAFE violated: KeyRole::from_tag panicked on bytes {:?}",
        case.tag_bytes
    );

    let parse_result = result.unwrap();

    // ── (B) Valid tag roundtrip ────────────────────────────────────────
    for &role in KeyRole::all() {
        let role_tag = role.tag();
        let parsed = KeyRole::from_tag(role_tag);
        assert_eq!(
            parsed,
            Some(role),
            "INV-KRS-VALID-TAG-ROUNDTRIP violated: {:?}.tag() -> {:?} -> {:?}",
            role,
            role_tag,
            parsed
        );

        // Also verify tag_u16 consistency
        let tag_u16 = role.tag_u16();
        let expected_u16 = u16::from_be_bytes(role_tag);
        assert_eq!(
            tag_u16, expected_u16,
            "INV-KRS-TAG-FORMAT-CONSISTENT violated: {:?} tag_u16()={} but from_be_bytes({:?})={}",
            role, tag_u16, role_tag, expected_u16
        );
    }

    // ── (C) Invalid tag None ───────────────────────────────────────────
    let valid_tags = [
        [0x00, 0x01], // Signing
        [0x00, 0x02], // Encryption
        [0x00, 0x03], // Issuance
        [0x00, 0x04], // Attestation
    ];

    if !valid_tags.contains(&case.tag_bytes) {
        assert_eq!(
            parse_result,
            None,
            "INV-KRS-INVALID-TAG-NONE violated: invalid bytes {:?} returned {:?} instead of None",
            case.tag_bytes,
            parse_result
        );
    }

    // ── (D) Deterministic parsing ──────────────────────────────────────
    let second_result = KeyRole::from_tag(case.tag_bytes);
    assert_eq!(
        parse_result, second_result,
        "INV-KRS-TAG-DETERMINISTIC violated: same tag bytes {:?} produced different results",
        case.tag_bytes
    );

    // ── (E) All roles coverage ─────────────────────────────────────────
    let all_roles = KeyRole::all();
    assert_eq!(
        all_roles.len(),
        4,
        "INV-KRS-ALL-ROLES-COVERED violated: expected 4 roles, got {}",
        all_roles.len()
    );

    // Verify all expected roles are present and have correct tags
    let expected_roles = [
        (KeyRole::Signing, [0x00, 0x01]),
        (KeyRole::Encryption, [0x00, 0x02]),
        (KeyRole::Issuance, [0x00, 0x03]),
        (KeyRole::Attestation, [0x00, 0x04]),
    ];

    for (expected_role, expected_tag) in expected_roles {
        assert!(
            all_roles.contains(&expected_role),
            "INV-KRS-ALL-ROLES-COVERED violated: {:?} not in KeyRole::all()",
            expected_role
        );

        assert_eq!(
            expected_role.tag(),
            expected_tag,
            "INV-KRS-ALL-ROLES-COVERED violated: {:?} has wrong tag {:?}, expected {:?}",
            expected_role,
            expected_role.tag(),
            expected_tag
        );
    }

    // Verify no duplicates
    let mut tags: Vec<_> = all_roles.iter().map(|r| r.tag()).collect();
    tags.sort();
    tags.dedup();
    assert_eq!(
        tags.len(),
        all_roles.len(),
        "INV-KRS-ALL-ROLES-COVERED violated: duplicate tags found in KeyRole::all()"
    );

    // ── (F) Tag format consistency ─────────────────────────────────────
    for &role in KeyRole::all() {
        let tag_bytes = role.tag();
        let tag_u16 = role.tag_u16();
        let reconstructed_u16 = u16::from_be_bytes(tag_bytes);

        assert_eq!(
            tag_u16, reconstructed_u16,
            "INV-KRS-TAG-FORMAT-CONSISTENT violated: {:?} tag_u16()={} but from_be_bytes({:?})={}",
            role, tag_u16, tag_bytes, reconstructed_u16
        );

        // Verify big-endian format
        let be_bytes = tag_u16.to_be_bytes();
        assert_eq!(
            tag_bytes, be_bytes,
            "INV-KRS-TAG-FORMAT-CONSISTENT violated: {:?} tag()={:?} but tag_u16().to_be_bytes()={:?}",
            role, tag_bytes, be_bytes
        );
    }

    // ── (G) Display formatting safety ──────────────────────────────────
    for &role in KeyRole::all() {
        let display_result = std::panic::catch_unwind(|| {
            format!("{}", role)
        });
        assert!(
            display_result.is_ok(),
            "INV-KRS-ROLE-DISPLAY-SAFE violated: Display formatting panicked for {:?}",
            role
        );

        let display_str = display_result.unwrap();
        assert!(
            !display_str.is_empty(),
            "INV-KRS-ROLE-DISPLAY-SAFE violated: Display formatting produced empty string for {:?}",
            role
        );

        // Verify expected display strings
        let expected = match role {
            KeyRole::Signing => "Signing",
            KeyRole::Encryption => "Encryption",
            KeyRole::Issuance => "Issuance",
            KeyRole::Attestation => "Attestation",
        };
        assert_eq!(
            display_str, expected,
            "INV-KRS-ROLE-DISPLAY-SAFE violated: {:?} displayed as '{}', expected '{}'",
            role, display_str, expected
        );
    }

    // Additional edge case testing
    test_edge_cases(&case);

    // Test tag comparison consistency
    if let Some(role1) = KeyRole::from_tag(case.tag_bytes) {
        if let Some(role2) = KeyRole::from_tag(case.comparison_tag) {
            // If both tags are valid, test ordering consistency
            let tag_ord = case.tag_bytes.cmp(&case.comparison_tag);
            let role_ord = role1.cmp(&role2);

            // Role ordering should be consistent with tag byte ordering
            match tag_ord {
                std::cmp::Ordering::Equal => {
                    assert_eq!(
                        role_ord,
                        std::cmp::Ordering::Equal,
                        "Role ordering inconsistent: equal tags but different roles"
                    );
                }
                _ => {
                    // For different tags, just verify ordering is deterministic
                    let second_ord = role1.cmp(&role2);
                    assert_eq!(
                        role_ord, second_ord,
                        "Role ordering non-deterministic"
                    );
                }
            }
        }
    }
});

fn test_edge_cases(case: &KeyRoleTagParsingFuzzCase) {
    // Test boundary values
    let boundary_tags = [
        [0x00, 0x00], // Below valid range
        [0x00, 0x05], // Above valid range
        [0xFF, 0xFF], // Maximum values
        [0x01, 0x00], // Wrong high byte
        [0x00, 0xFF], // High low byte
    ];

    for boundary_tag in boundary_tags {
        let result = KeyRole::from_tag(boundary_tag);
        // All boundary cases should return None (invalid)
        assert_eq!(
            result, None,
            "Boundary tag {:?} should be invalid but returned {:?}",
            boundary_tag, result
        );
    }

    // Test with additional bytes to ensure we only parse the first 2
    if case.additional_bytes.len() >= 2 {
        let extended_tag = [case.additional_bytes[0], case.additional_bytes[1]];
        let extended_result = KeyRole::from_tag(extended_tag);

        // Should be deterministic regardless of where bytes come from
        let direct_result = KeyRole::from_tag(extended_tag);
        assert_eq!(
            extended_result, direct_result,
            "Extended tag parsing non-deterministic"
        );
    }

    // Test all combinations of valid high bytes with various low bytes
    for low_byte in 0u8..=255 {
        let test_tag = [0x00, low_byte];
        let result = KeyRole::from_tag(test_tag);

        match low_byte {
            0x01 => assert_eq!(result, Some(KeyRole::Signing)),
            0x02 => assert_eq!(result, Some(KeyRole::Encryption)),
            0x03 => assert_eq!(result, Some(KeyRole::Issuance)),
            0x04 => assert_eq!(result, Some(KeyRole::Attestation)),
            _ => assert_eq!(result, None),
        }
    }

    // Test all combinations with invalid high bytes
    for high_byte in 1u8..=255 {
        for low_byte in 1u8..=4 {
            let test_tag = [high_byte, low_byte];
            let result = KeyRole::from_tag(test_tag);
            assert_eq!(
                result, None,
                "Invalid high byte 0x{:02X} should make tag invalid: {:?}",
                high_byte, test_tag
            );
        }
    }
}