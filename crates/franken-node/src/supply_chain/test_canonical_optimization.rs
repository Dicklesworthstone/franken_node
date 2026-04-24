//! Test to verify canonical encoding optimization preserves exact output

use super::trust_card::canonicalize_value;
use hex;
use serde_json::{Map, Value};
use sha2::Digest;
use std::collections::BTreeSet;

// Optimized implementation for testing
fn canonicalize_value_optimized(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort_unstable(); // More efficient than BTreeSet

            let mut out = Map::with_capacity(keys.len()); // Pre-allocate
            for key in keys {
                if let Some(val) = map.get(&key) {
                    out.insert(key, canonicalize_value_optimized(val.clone()));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(canonicalize_value_optimized)
                .collect(),
        ),
        _ => value,
    }
}

#[cfg(test)]
mod optimization_tests {
    use super::{canonicalize_value, canonicalize_value_optimized};

    #[test]
    fn test_canonical_optimization_isomorphism() {
        let test_cases = vec![
            serde_json::json!({
                "z_last": "value_z",
                "a_first": "value_a",
                "m_middle": "value_m"
            }),
            serde_json::json!({
                "outer": {
                    "z_nested": "nested_z",
                    "a_nested": "nested_a"
                },
                "array": ["c", "a", "b"],
                "primitive": 42
            }),
            serde_json::json!({
                "extension": {
                    "extension_id": "npm:@acme/plugin",
                    "version": "1.0.0"
                },
                "publisher": {
                    "publisher_id": "acme-corp",
                    "display_name": "ACME Corporation"
                }
            }),
        ];

        for (i, test_case) in test_cases.into_iter().enumerate() {
            let current = canonicalize_value(test_case.clone());
            let optimized = canonicalize_value_optimized(test_case);

            let current_json = serde_json::to_string(&current).unwrap();
            let optimized_json = serde_json::to_string(&optimized).unwrap();

            assert_eq!(
                current_json, optimized_json,
                "JSON output must be identical for case {}",
                i
            );

            // Verify hash equivalence
            let current_hash = {
                let mut hasher = sha2::Sha256::new();
                hasher.update(b"trust_card_hash_v1:");
                hasher.update(current_json.as_bytes());
                hex::encode(hasher.finalize())
            };

            let optimized_hash = {
                let mut hasher = sha2::Sha256::new();
                hasher.update(b"trust_card_hash_v1:");
                hasher.update(optimized_json.as_bytes());
                hex::encode(hasher.finalize())
            };

            assert_eq!(
                current_hash, optimized_hash,
                "Hash must be identical for case {}",
                i
            );
        }
    }
}
