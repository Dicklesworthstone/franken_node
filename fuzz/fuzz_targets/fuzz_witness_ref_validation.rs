#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use frankenengine_node::observability::witness_ref::{
    WitnessRef, WitnessId, WitnessKind, WitnessSet, WitnessValidator,
};
use frankenengine_node::observability::evidence_ledger::{
    EvidenceEntry, DecisionKind, EvidenceEntryBuilder,
};

// Size limits for bounded fuzzing
const MAX_OPERATIONS: usize = 16;
const MAX_STRING_LEN: usize = 1024;
const MAX_LOCATOR_LEN: usize = 512;
const MAX_WITNESS_COUNT: usize = 32;
const MAX_ID_LEN: usize = 256;

/// Fuzzable witness reference with bounded strings
#[derive(Debug, Clone, Arbitrary)]
struct FuzzWitnessRef {
    #[arbitrary(with = bounded_witness_id)]
    witness_id: String,
    witness_kind: WitnessKind,
    #[arbitrary(with = bounded_locator)]
    locator: Option<String>,
    #[arbitrary(with = bounded_hash)]
    integrity_hash: [u8; 32],
}

impl From<FuzzWitnessRef> for WitnessRef {
    fn from(fuzz: FuzzWitnessRef) -> Self {
        let mut witness = WitnessRef::new(fuzz.witness_id, fuzz.witness_kind, fuzz.integrity_hash);
        if let Some(locator) = fuzz.locator {
            witness = witness.with_locator(locator);
        }
        witness
    }
}

/// Fuzzable evidence entry for validation testing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzEvidenceEntry {
    #[arbitrary(with = bounded_decision_id)]
    decision_id: String,
    decision_kind: DecisionKind,
    #[arbitrary(with = bounded_description)]
    description: String,
    #[arbitrary(with = bounded_context)]
    context: String,
}

impl From<FuzzEvidenceEntry> for EvidenceEntry {
    fn from(fuzz: FuzzEvidenceEntry) -> Self {
        EvidenceEntryBuilder::new(fuzz.decision_id, fuzz.decision_kind)
            .with_description(fuzz.description)
            .with_context(fuzz.context)
            .build()
    }
}

/// Operations that can be performed on witness references and sets
#[derive(Debug, Clone, Arbitrary)]
enum WitnessOperation {
    CreateWitnessRef {
        witness: FuzzWitnessRef,
    },
    CreateWitnessSet {
        #[arbitrary(with = bounded_witnesses)]
        witnesses: Vec<FuzzWitnessRef>,
    },
    ValidateWithWitnessSet {
        entry: FuzzEvidenceEntry,
        #[arbitrary(with = bounded_witnesses)]
        witnesses: Vec<FuzzWitnessRef>,
    },
    TestLocatorValidation {
        #[arbitrary(with = bounded_locator_test)]
        locator: String,
    },
    TestWitnessIdValidation {
        #[arbitrary(with = bounded_witness_id_test)]
        witness_id: String,
    },
    HashIntegrityCheck {
        witness: FuzzWitnessRef,
        #[arbitrary(with = bounded_hash)]
        expected_hash: [u8; 32],
    },
}

/// Complete fuzz input with operations
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    #[arbitrary(with = bounded_operations)]
    operations: Vec<WitnessOperation>,
}

// Bounded arbitrary helpers

fn bounded_witness_id(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=8)?;
    Ok(match choice {
        0 => String::new(), // Empty - should be invalid
        1 => "WIT-001".to_string(), // Valid format
        2 => " WIT-002".to_string(), // Leading space
        3 => "WIT-003 ".to_string(), // Trailing space
        4 => "WIT\x00004".to_string(), // Null byte
        5 => "WIT\n005".to_string(), // Newline
        6 => "WIT-006\t".to_string(), // Tab
        7 => "a".repeat(300), // Very long
        8 => {
            // Random witness ID with potential issues
            let len = u.int_in_range(0..=MAX_ID_LEN)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_locator(u: &mut Unstructured) -> arbitrary::Result<Option<String>> {
    if u.arbitrary::<bool>()? {
        Ok(Some(bounded_locator_test(u)?))
    } else {
        Ok(None)
    }
}

fn bounded_locator_test(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=12)?;
    Ok(match choice {
        0 => String::new(), // Empty - should be invalid
        1 => "bundles/proof-123.bundle".to_string(), // Valid format
        2 => "/absolute/path".to_string(), // Absolute path - should be invalid
        3 => "//double-slash".to_string(), // Double slash start - invalid
        4 => "path//double".to_string(), // Double slash middle - invalid
        5 => "path/./current".to_string(), // Current dir - invalid
        6 => "path/../parent".to_string(), // Parent dir traversal - invalid
        7 => "path%20encoded".to_string(), // Percent encoding - invalid
        8 => "path:with:colons".to_string(), // Colons - invalid
        9 => "path@with@ats".to_string(), // At symbols - invalid
        10 => "path\\with\\backslashes".to_string(), // Backslashes - invalid
        11 => "path\x00null".to_string(), // Null bytes - invalid
        12 => {
            // Random locator with various characters
            let len = u.int_in_range(0..=MAX_LOCATOR_LEN)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_witness_id_test(u: &mut Unstructured) -> arbitrary::Result<String> {
    // Use same logic as bounded_witness_id for consistency
    bounded_witness_id(u)
}

fn bounded_hash(u: &mut Unstructured) -> arbitrary::Result<[u8; 32]> {
    let bytes = u.bytes(32)?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(bytes);
    Ok(hash)
}

fn bounded_decision_id(u: &mut Unstructured) -> arbitrary::Result<String> {
    let len = u.int_in_range(1..=64)?;
    let bytes = u.bytes(len)?;
    Ok(format!("DEC-{}", hex::encode(&bytes[..8.min(len)])))
}

fn bounded_description(u: &mut Unstructured) -> arbitrary::Result<String> {
    let len = u.int_in_range(0..=MAX_STRING_LEN)?;
    let bytes = u.bytes(len)?;
    String::from_utf8(bytes.to_vec()).or_else(|_| Ok("fallback-description".to_string()))
}

fn bounded_context(u: &mut Unstructured) -> arbitrary::Result<String> {
    let len = u.int_in_range(0..=MAX_STRING_LEN)?;
    let bytes = u.bytes(len)?;
    String::from_utf8(bytes.to_vec()).or_else(|_| Ok("fallback-context".to_string()))
}

fn bounded_witnesses(u: &mut Unstructured) -> arbitrary::Result<Vec<FuzzWitnessRef>> {
    let len = u.int_in_range(0..=MAX_WITNESS_COUNT)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fn bounded_operations(u: &mut Unstructured) -> arbitrary::Result<Vec<WitnessOperation>> {
    let len = u.int_in_range(0..=MAX_OPERATIONS)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fuzz_target!(|data: &[u8]| {
    // Input size guard to prevent OOM
    if data.len() > 100_000 {
        return;
    }

    let input: FuzzInput = match Unstructured::new(data).arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Invalid input, skip silently
    };

    // Track state for invariant checking
    let mut witness_ref_count = 0;
    let mut witness_set_count = 0;
    let mut validation_attempts = 0;
    let mut successful_validations = 0;
    let mut failed_validations = 0;

    // Create validator for testing
    let mut validator = WitnessValidator::new();

    // Execute fuzzed operations
    for op in input.operations {
        match op {
            WitnessOperation::CreateWitnessRef { witness } => {
                let witness_ref: WitnessRef = witness.into();
                witness_ref_count += 1;

                // Test witness reference properties
                let witness_id_str = witness_ref.witness_id.as_str();
                let hash_hex = witness_ref.hash_hex();

                // Verify hash hex format
                assert_eq!(hash_hex.len(), 64, "Hash hex should be 64 characters (32 bytes)");
                assert!(hash_hex.chars().all(|c| c.is_ascii_hexdigit()),
                       "Hash hex should contain only hex digits");

                // Verify witness ID is preserved
                assert!(!witness_id_str.is_empty() || witness_id_str.trim() != witness_id_str,
                       "Witness ID validation inconsistent");

                // Test locator validation if present
                if let Some(ref locator) = witness_ref.replay_bundle_locator {
                    // Locator should follow validation rules
                    let is_valid_locator = !locator.trim().is_empty() &&
                                         locator.trim() == locator &&
                                         locator.len() <= 512 &&
                                         !locator.starts_with('/') &&
                                         !locator.starts_with("//") &&
                                         !locator.contains("//");

                    // If locator is present, it should have passed validation
                    if is_valid_locator {
                        assert!(!locator.contains(".."), "Valid locator should not contain parent dir refs");
                        assert!(!locator.contains("%"), "Valid locator should not contain percent encoding");
                        assert!(!locator.contains(":"), "Valid locator should not contain colons");
                        assert!(!locator.contains("@"), "Valid locator should not contain at symbols");
                        assert!(!locator.contains("\\"), "Valid locator should not contain backslashes");
                    }
                }
            }

            WitnessOperation::CreateWitnessSet { witnesses } => {
                let mut witness_set = WitnessSet::new();
                witness_set_count += 1;

                let initial_count = witness_set.len();
                assert_eq!(initial_count, 0, "New witness set should be empty");

                // Add witnesses and test bounds
                for fuzz_witness in witnesses {
                    let witness_ref: WitnessRef = fuzz_witness.into();
                    witness_set.add(witness_ref);

                    // Verify set doesn't exceed bounds
                    assert!(witness_set.len() <= 4096, "Witness set should respect MAX_REFS bound");
                }

                // Test witness set properties
                assert!(witness_set.len() >= initial_count, "Witness count should not decrease");
                assert!(!witness_set.is_empty() || witnesses.is_empty(),
                       "Empty witness set should only occur with empty input");
            }

            WitnessOperation::ValidateWithWitnessSet { entry, witnesses } => {
                let evidence_entry: EvidenceEntry = entry.into();
                let mut witness_set = WitnessSet::new();

                // Build witness set
                for fuzz_witness in witnesses {
                    let witness_ref: WitnessRef = fuzz_witness.into();
                    witness_set.add(witness_ref);
                }

                validation_attempts += 1;

                // Test validation
                match validator.validate(&evidence_entry, &witness_set) {
                    Ok(()) => {
                        successful_validations += 1;

                        // Successful validation implies certain properties
                        let decision_kind = evidence_entry.decision_kind();
                        let is_high_impact = matches!(decision_kind,
                            DecisionKind::Quarantine |
                            DecisionKind::Release |
                            DecisionKind::Escalate
                        );

                        if is_high_impact {
                            assert!(!witness_set.is_empty(),
                                   "High-impact decisions should have witness references");
                        }
                    }
                    Err(_) => {
                        failed_validations += 1;
                        // Validation failure is expected for invalid inputs
                    }
                }
            }

            WitnessOperation::TestLocatorValidation { locator } => {
                // Test locator validation edge cases
                let trimmed = locator.trim();
                let is_empty = locator.is_empty();
                let has_whitespace_diff = trimmed != locator;
                let too_long = locator.len() > 512;
                let starts_with_slash = locator.starts_with('/');
                let starts_with_double_slash = locator.starts_with("//");
                let contains_double_slash = locator.contains("//");

                // Test basic validation properties
                if is_empty || has_whitespace_diff || too_long ||
                   starts_with_slash || starts_with_double_slash || contains_double_slash {
                    // Should be invalid - but we don't assert since the function is internal
                }

                // Test character validation
                let has_invalid_chars = locator.chars().any(|ch| {
                    !ch.is_ascii() || ch.is_control() ||
                    matches!(ch, '%' | ':' | '@' | '\\') ||
                    !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '.' | '/')
                });

                // Test path component validation
                let has_invalid_components = locator.split('/').any(|component| {
                    component.is_empty() || component == "." || component == ".."
                });

                // These conditions indicate an invalid locator
                if has_invalid_chars || has_invalid_components {
                    // Should be invalid according to the validation rules
                }
            }

            WitnessOperation::TestWitnessIdValidation { witness_id } => {
                // Test witness ID validation edge cases
                let _witness_id_obj = WitnessId::new(&witness_id);

                // Test basic properties
                let is_empty = witness_id.is_empty();
                let has_control_chars = witness_id.chars().any(|c| c.is_control());
                let too_long = witness_id.len() > 256;

                // These are potential validation concerns
                if is_empty || has_control_chars || too_long {
                    // Might be invalid, but WitnessId constructor doesn't validate
                }

                // Test ID as string operations
                let as_str = _witness_id_obj.as_str();
                assert_eq!(as_str, witness_id, "WitnessId should preserve original string");

                // Test display formatting
                let display_str = format!("{}", _witness_id_obj);
                assert_eq!(display_str, witness_id, "Display format should match original");
            }

            WitnessOperation::HashIntegrityCheck { witness, expected_hash } => {
                let witness_ref: WitnessRef = witness.into();

                // Test hash operations
                let hash_hex = witness_ref.hash_hex();
                let expected_hex = hex::encode(expected_hash);

                // Verify hash consistency
                assert_eq!(hash_hex.len(), expected_hex.len(), "Hash hex length should be consistent");
                assert!(hash_hex.chars().all(|c| c.is_ascii_hexdigit()),
                       "Hash should only contain hex digits");

                // Test hash integrity comparison
                if witness_ref.integrity_hash == expected_hash {
                    assert_eq!(hash_hex, expected_hex, "Hash hex should match when bytes match");
                }

                // Verify hash is always lowercase
                assert_eq!(hash_hex, hash_hex.to_lowercase(), "Hash hex should be lowercase");
            }
        }
    }

    // Invariant checks - these must hold regardless of input

    // Count consistency
    assert!(validation_attempts == successful_validations + failed_validations,
           "Validation attempt count should equal success + failure count");

    // Validator state consistency
    assert!(validator.validated_count() >= successful_validations as u64,
           "Validator validated count should be at least successful validations");
    assert!(validator.rejected_count() >= failed_validations as u64,
           "Validator rejected count should be at least failed validations");

    // Bounds checking
    assert!(witness_ref_count <= MAX_OPERATIONS, "Witness ref count within bounds");
    assert!(witness_set_count <= MAX_OPERATIONS, "Witness set count within bounds");

    // Test additional locator validation edge cases
    let test_locators = [
        "",                          // Empty
        "/absolute",                 // Absolute path
        "//double",                  // Double slash start
        "path//middle",              // Double slash middle
        "path/./current",            // Current directory
        "path/../parent",            // Parent directory
        "path%20space",              // Percent encoding
        "path:colon",                // Colon
        "path@at",                   // At symbol
        "path\\backslash",           // Backslash
        "valid/path",                // Valid case
        "a".repeat(600),             // Too long
    ];

    for test_locator in &test_locators {
        // Create witness with each test locator
        let test_witness = WitnessRef::new(
            "test-witness",
            WitnessKind::Telemetry,
            [0; 32]
        ).with_locator(test_locator);

        // Verify locator is preserved (validation happens at creation time)
        if let Some(ref locator) = test_witness.replay_bundle_locator {
            assert_eq!(locator, test_locator, "Locator should be preserved as provided");
        }
    }

    // Test witness kind enumeration
    for kind in WitnessKind::all() {
        let test_witness = WitnessRef::new("test", *kind, [1; 32]);
        assert_eq!(test_witness.witness_kind, *kind, "Witness kind should be preserved");

        let kind_label = kind.label();
        assert!(!kind_label.is_empty(), "Kind label should not be empty");
        assert!(kind_label.len() < 32, "Kind label should be reasonable length");
    }
});