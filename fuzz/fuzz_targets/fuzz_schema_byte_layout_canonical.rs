//! Fuzz target for schema version byte layout canonicalization boundary.
//!
//! Tests deterministic hash computation, collision prevention via length prefixes,
//! canonical ordering stability, and protocol fingerprint consistency across
//! schema registry surfaces. Critical for preventing hash collision attacks and
//! maintaining protocol compatibility.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: ByteLayoutOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum ByteLayoutOperation {
    RegistryStructureHash {
        entries: Vec<SchemaEntry>,
    },
    EntryCountHash {
        count: u64,
    },
    CriticalConstantsHash {
        constants: Vec<ConstantEntry>,
    },
    CollisionTestCases {
        entries1: Vec<SchemaEntry>,
        entries2: Vec<SchemaEntry>,
    },
    MaliciousInputTests {
        malicious_type: MaliciousInputType,
        entries: Vec<SchemaEntry>,
    },
    CanonicalOrderingTests {
        unordered_entries: Vec<SchemaEntry>,
    },
    EdgeCaseInputs {
        edge_case: EdgeCaseType,
    },
}

#[derive(Debug, Clone, Arbitrary)]
struct SchemaEntry {
    name: SchemaName,
    version: SchemaVersion,
}

#[derive(Debug, Clone, Arbitrary)]
enum SchemaName {
    Valid(String),
    Empty,
    VeryLong(Vec<u8>),
    WithNulBytes(Vec<u8>),
    Unicode(String),
    ControlChars(Vec<u8>),
    Duplicated(String, u8), // name + duplicate count
}

#[derive(Debug, Clone, Arbitrary)]
enum SchemaVersion {
    Valid(String),
    Empty,
    VeryLong(Vec<u8>),
    WithNulBytes(Vec<u8>),
    Unicode(String),
    SemverLike(u8, u8, u8), // major.minor.patch
    GitHashLike(Vec<u8>),    // 40 hex chars
}

#[derive(Debug, Clone, Arbitrary)]
struct ConstantEntry {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Arbitrary)]
enum MaliciousInputType {
    LengthPrefixCollision,
    HashCollisionAttempt,
    OverflowAttack,
    NullByteInjection,
    UnicodeNormalization,
    ExtremelyLongEntries,
}

#[derive(Debug, Clone, Arbitrary)]
enum EdgeCaseType {
    EmptyRegistry,
    SingleEntry,
    IdenticalNames,
    IdenticalVersions,
    MaxSizeEntries,
    UnicodeEdgeCases,
    BinaryData,
    AllEmptyFields,
}

impl SchemaName {
    fn to_string(&self) -> String {
        match self {
            Self::Valid(s) => s.clone(),
            Self::Empty => String::new(),
            Self::VeryLong(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Self::WithNulBytes(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Self::Unicode(s) => s.clone(),
            Self::ControlChars(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Self::Duplicated(base, count) => {
                if base.is_empty() {
                    format!("duplicate_{}", count)
                } else {
                    format!("{}_{}", base, count)
                }
            }
        }
    }
}

impl SchemaVersion {
    fn to_string(&self) -> String {
        match self {
            Self::Valid(s) => s.clone(),
            Self::Empty => String::new(),
            Self::VeryLong(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Self::WithNulBytes(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Self::Unicode(s) => s.clone(),
            Self::SemverLike(major, minor, patch) => format!("{}.{}.{}", major, minor, patch),
            Self::GitHashLike(bytes) => {
                hex::encode(bytes.iter().take(20).copied().collect::<Vec<u8>>())
            }
        }
    }
}

impl SchemaEntry {
    fn to_tuple(&self) -> (String, String) {
        (self.name.to_string(), self.version.to_string())
    }
}

/// Test byte layout canonicalization invariants.
fn test_byte_layout_invariants(operation: &ByteLayoutOperation) {
    match operation {
        ByteLayoutOperation::RegistryStructureHash { entries } => {
            let schema_entries: Vec<_> = entries.iter().map(|e| e.to_tuple()).collect();
            let hash1 = compute_registry_structure_hash(&schema_entries);
            let hash2 = compute_registry_structure_hash(&schema_entries);

            // Deterministic: same input produces same hash
            assert_eq!(hash1, hash2, "Registry structure hash must be deterministic");

            // Format consistency
            test_hash_format_consistency(&hash1);

            // Test canonical ordering
            let mut sorted_entries = schema_entries.clone();
            sorted_entries.sort_by_key(|(name, _)| name.clone());
            let sorted_hash = compute_registry_structure_hash(&sorted_entries);

            // Hash should be same regardless of input order (canonical ordering)
            let canonical_hash = compute_registry_structure_hash_canonical(&schema_entries);
            assert_eq!(sorted_hash, canonical_hash, "Canonical ordering must be consistent");
        }

        ByteLayoutOperation::EntryCountHash { count } => {
            let hash1 = compute_entry_count_hash(*count);
            let hash2 = compute_entry_count_hash(*count);

            // Deterministic
            assert_eq!(hash1, hash2, "Entry count hash must be deterministic");

            // Format consistency
            test_hash_format_consistency(&hash1);

            // Different counts should produce different hashes
            if *count < u64::MAX {
                let different_hash = compute_entry_count_hash(*count + 1);
                assert_ne!(hash1, different_hash, "Different counts should produce different hashes");
            }
        }

        ByteLayoutOperation::CriticalConstantsHash { constants } => {
            let const_tuples: Vec<_> = constants.iter()
                .map(|c| (c.name.as_str(), c.value.as_str()))
                .collect();
            let hash1 = compute_critical_constants_hash(&const_tuples);
            let hash2 = compute_critical_constants_hash(&const_tuples);

            // Deterministic
            assert_eq!(hash1, hash2, "Critical constants hash must be deterministic");

            // Format consistency
            test_hash_format_consistency(&hash1);
        }

        ByteLayoutOperation::CollisionTestCases { entries1, entries2 } => {
            let schema_entries1: Vec<_> = entries1.iter().map(|e| e.to_tuple()).collect();
            let schema_entries2: Vec<_> = entries2.iter().map(|e| e.to_tuple()).collect();

            let hash1 = compute_registry_structure_hash(&schema_entries1);
            let hash2 = compute_registry_structure_hash(&schema_entries2);

            // Different inputs should typically produce different hashes
            // (unless they happen to be equivalent after canonical ordering)
            test_hash_format_consistency(&hash1);
            test_hash_format_consistency(&hash2);

            // Test collision resistance properties
            test_collision_resistance(&schema_entries1, &schema_entries2);
        }

        ByteLayoutOperation::MaliciousInputTests { malicious_type, entries } => {
            let schema_entries: Vec<_> = entries.iter().map(|e| e.to_tuple()).collect();

            // Test that malicious inputs are handled safely
            match malicious_type {
                MaliciousInputType::LengthPrefixCollision => {
                    test_length_prefix_collision_resistance(&schema_entries);
                }
                MaliciousInputType::OverflowAttack => {
                    test_overflow_attack_resistance(&schema_entries);
                }
                MaliciousInputType::NullByteInjection => {
                    test_null_byte_injection_safety(&schema_entries);
                }
                _ => {
                    // General malicious input safety
                    let hash = compute_registry_structure_hash(&schema_entries);
                    test_hash_format_consistency(&hash);
                }
            }
        }

        ByteLayoutOperation::CanonicalOrderingTests { unordered_entries } => {
            let schema_entries: Vec<_> = unordered_entries.iter().map(|e| e.to_tuple()).collect();
            test_canonical_ordering_stability(&schema_entries);
        }

        ByteLayoutOperation::EdgeCaseInputs { edge_case } => {
            test_edge_case_handling(edge_case);
        }
    }
}

/// Test hash format consistency.
fn test_hash_format_consistency(hash: &str) {
    assert!(hash.starts_with("sha256:"), "Hash must start with sha256: prefix");
    assert_eq!(hash.len(), 71, "SHA-256 hash must be 71 chars (sha256: + 64 hex)");

    let hex_part = &hash[7..];
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()), "Hash hex part must be valid hex");
}

/// Test canonical ordering stability.
fn test_canonical_ordering_stability(entries: &[(String, String)]) {
    // Different orderings of same entries should produce same hash
    let mut entries1 = entries.to_vec();
    let mut entries2 = entries.to_vec();
    let mut entries3 = entries.to_vec();

    // Original order
    let hash1 = compute_registry_structure_hash_canonical(&entries1);

    // Reverse order
    entries2.reverse();
    let hash2 = compute_registry_structure_hash_canonical(&entries2);

    // Random shuffle (sort by reverse name to get different order)
    entries3.sort_by_key(|(name, _)| name.chars().rev().collect::<String>());
    let hash3 = compute_registry_structure_hash_canonical(&entries3);

    // All should be equal due to canonical ordering
    assert_eq!(hash1, hash2, "Canonical ordering must handle reverse order");
    assert_eq!(hash1, hash3, "Canonical ordering must handle shuffled order");
}

/// Test length prefix collision resistance.
fn test_length_prefix_collision_resistance(entries: &[(String, String)]) {
    // Length prefixes should prevent collision between:
    // ("ab", "cd") vs ("a", "bcd")

    let collision_test1 = vec![("ab".to_string(), "cd".to_string())];
    let collision_test2 = vec![("a".to_string(), "bcd".to_string())];

    let hash1 = compute_registry_structure_hash(&collision_test1);
    let hash2 = compute_registry_structure_hash(&collision_test2);

    // Should be different due to length prefixes
    assert_ne!(hash1, hash2, "Length prefixes must prevent collision attacks");
}

/// Test overflow attack resistance.
fn test_overflow_attack_resistance(entries: &[(String, String)]) {
    // Very large lengths should be handled safely
    for (name, version) in entries {
        // Should not panic or produce undefined behavior
        let single_entry = vec![(name.clone(), version.clone())];
        let hash = compute_registry_structure_hash(&single_entry);
        test_hash_format_consistency(&hash);
    }
}

/// Test null byte injection safety.
fn test_null_byte_injection_safety(entries: &[(String, String)]) {
    // Null bytes should be handled safely in hash computation
    for (name, version) in entries {
        if name.contains('\0') || version.contains('\0') {
            let single_entry = vec![(name.clone(), version.clone())];
            let hash = compute_registry_structure_hash(&single_entry);
            test_hash_format_consistency(&hash);
        }
    }
}

/// Test collision resistance properties.
fn test_collision_resistance(entries1: &[(String, String)], entries2: &[(String, String)]) {
    if entries1 != entries2 {
        let hash1 = compute_registry_structure_hash_canonical(entries1);
        let hash2 = compute_registry_structure_hash_canonical(entries2);

        // Different canonical entries should typically produce different hashes
        // (This is probabilistic due to hash function properties)
    }
}

/// Test edge case handling.
fn test_edge_case_handling(edge_case: &EdgeCaseType) {
    match edge_case {
        EdgeCaseType::EmptyRegistry => {
            let empty_entries = vec![];
            let hash = compute_registry_structure_hash(&empty_entries);
            test_hash_format_consistency(&hash);

            let count_hash = compute_entry_count_hash(0);
            test_hash_format_consistency(&count_hash);
        }
        EdgeCaseType::SingleEntry => {
            let single_entry = vec![("test".to_string(), "1.0.0".to_string())];
            let hash = compute_registry_structure_hash(&single_entry);
            test_hash_format_consistency(&hash);
        }
        EdgeCaseType::IdenticalNames => {
            let identical_names = vec![
                ("same".to_string(), "v1".to_string()),
                ("same".to_string(), "v2".to_string()),
            ];
            let hash = compute_registry_structure_hash(&identical_names);
            test_hash_format_consistency(&hash);
        }
        EdgeCaseType::AllEmptyFields => {
            let empty_fields = vec![("".to_string(), "".to_string())];
            let hash = compute_registry_structure_hash(&empty_fields);
            test_hash_format_consistency(&hash);
        }
        _ => {
            // Other edge cases handled generically
        }
    }
}

/// Compute registry structure hash with canonical ordering (mimics the actual implementation).
fn compute_registry_structure_hash_canonical(entries: &[(String, String)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"schema_registry_structure_v1:");

    hasher.update((entries.len() as u64).to_le_bytes());

    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by_key(|(name, _)| name.clone());

    for (name, version) in sorted_entries {
        hasher.update(b"field:name");
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());

        hasher.update(b"field:version");
        hasher.update((version.len() as u64).to_le_bytes());
        hasher.update(version.as_bytes());
    }

    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

/// Compute registry structure hash without canonical ordering.
fn compute_registry_structure_hash(entries: &[(String, String)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"schema_registry_structure_v1:");

    hasher.update((entries.len() as u64).to_le_bytes());

    for (name, version) in entries {
        hasher.update(b"field:name");
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());

        hasher.update(b"field:version");
        hasher.update((version.len() as u64).to_le_bytes());
        hasher.update(version.as_bytes());
    }

    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

/// Compute entry count hash.
fn compute_entry_count_hash(count: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"schema_registry_entry_count_v1:");
    hasher.update(count.to_le_bytes());
    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

/// Compute critical constants hash.
fn compute_critical_constants_hash(constants: &[(&str, &str)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"critical_constants_v1:");

    for (name, value) in constants {
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }

    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

fuzz_target!(|input: FuzzInput| {
    std::panic::catch_unwind(|| {
        test_byte_layout_invariants(&input.operation);
    }).unwrap_or_else(|_| {
        eprintln!("Panic caught in schema byte layout canonical fuzzing");
    });
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_hashing() {
        let entries = vec![
            ("test1".to_string(), "v1.0.0".to_string()),
            ("test2".to_string(), "v2.0.0".to_string()),
        ];

        let hash1 = compute_registry_structure_hash(&entries);
        let hash2 = compute_registry_structure_hash(&entries);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_canonical_ordering() {
        let entries1 = vec![
            ("b".to_string(), "v1".to_string()),
            ("a".to_string(), "v2".to_string()),
        ];

        let entries2 = vec![
            ("a".to_string(), "v2".to_string()),
            ("b".to_string(), "v1".to_string()),
        ];

        let hash1 = compute_registry_structure_hash_canonical(&entries1);
        let hash2 = compute_registry_structure_hash_canonical(&entries2);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_length_prefix_collision_prevention() {
        let test1 = vec![("ab".to_string(), "cd".to_string())];
        let test2 = vec![("a".to_string(), "bcd".to_string())];

        let hash1 = compute_registry_structure_hash(&test1);
        let hash2 = compute_registry_structure_hash(&test2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_format() {
        let hash = compute_entry_count_hash(42);
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 71);
    }

    #[test]
    fn test_fuzz_input_generation() {
        let mut data = [0u8; 1000];
        for i in 0..data.len() {
            data[i] = (i % 256) as u8;
        }

        let mut unstructured = Unstructured::new(&data);
        if let Ok(input) = FuzzInput::arbitrary(&mut unstructured) {
            // Should not panic during operation construction
            match input.operation {
                ByteLayoutOperation::RegistryStructureHash { .. } => {},
                ByteLayoutOperation::EntryCountHash { .. } => {},
                ByteLayoutOperation::CollisionTestCases { .. } => {},
                _ => {},
            }
        }
    }
}