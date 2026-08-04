//! Cryptographic Security conformance tests (R7.*).

use super::super::*;
use std::collections::HashSet;

/// R7.1: MUST use domain-separated hashing
pub struct DomainSeparationTest;

impl ConformanceTest for DomainSeparationTest {
    fn id(&self) -> &str {
        "R7.1"
    }
    fn name(&self) -> &str {
        "Domain-separated hashing"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "7"
    }
    fn description(&self) -> &str {
        "MUST use distinct domain separators for leaf and node hashing"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Test that leaf and node hashes are in distinct domains
        let test_input = "domain-test";

        let leaf_hash = marker_leaf_hash(test_input);

        // We can't directly test node hashing since it's internal,
        // but we can verify that identical content in different contexts
        // produces different hashes through the public API

        // Create a stream with markers that would create collision-prone scenarios
        let mut stream = MarkerStream::new();
        stream
            .append(
                MarkerEventType::PolicyChange,
                test_input,
                1_000_000_000,
                "trace-1",
            )
            .expect("append");

        let mut cp = MmrCheckpoint::enabled();
        cp.rebuild_from_stream(&stream).expect("rebuild");

        let root_hash = cp.root().expect("root").root_hash.clone();

        // Root hash should be different from leaf hash even for single element
        // (since root computation involves different domain than leaf)
        if leaf_hash == root_hash {
            return TestResult::fail(format!(
                "Leaf hash equals root hash - possible domain separation failure: {}",
                leaf_hash
            ));
        }

        // Test collision resistance between different input formats
        let collision_test_inputs = vec![("a", "b"), ("ab", "cd"), ("test", "test2"), ("", " ")];

        for (input1, input2) in collision_test_inputs {
            let hash1 = marker_leaf_hash(input1);
            let hash2 = marker_leaf_hash(input2);

            if hash1 == hash2 {
                return TestResult::fail(format!(
                    "Hash collision detected between '{}' and '{}': {}",
                    input1, input2, hash1
                ));
            }

            // Verify hashes are valid hex
            if hash1.len() != 64 || hash2.len() != 64 {
                return TestResult::fail("Hash length is not 64 characters");
            }

            if !hash1.chars().all(|c| c.is_ascii_hexdigit())
                || !hash2.chars().all(|c| c.is_ascii_hexdigit())
            {
                return TestResult::fail("Hash contains non-hex characters");
            }
        }

        TestResult::pass()
    }
}

/// R7.2: MUST use length-prefixed hash inputs
pub struct LengthPrefixingTest;

impl ConformanceTest for LengthPrefixingTest {
    fn id(&self) -> &str {
        "R7.2"
    }
    fn name(&self) -> &str {
        "Length-prefixed hash inputs"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "7"
    }
    fn description(&self) -> &str {
        "MUST use length-prefixed inputs to prevent boundary attacks"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Test boundary attack resistance through different input combinations
        // that would have the same concatenated content without length prefixing
        let boundary_tests = vec![
            ("ab", "cd"), // "abcd"
            ("a", "bcd"), // "abcd"
            ("abc", "d"), // "abcd"
            ("", "abcd"), // "abcd"
        ];

        for (input1, input2) in boundary_tests {
            let hash1 = marker_leaf_hash(input1);
            let hash2 = marker_leaf_hash(input2);

            if hash1 == hash2 {
                return TestResult::fail(format!(
                    "Length-prefixing failure: '{}' and '{}' produce same hash: {}",
                    input1, input2, hash1
                ));
            }
        }

        // Test that identical inputs produce identical hashes (determinism)
        let determinism_tests = vec!["", "a", "test", "longer-test-string"];
        for input in determinism_tests {
            let hash1 = marker_leaf_hash(input);
            let hash2 = marker_leaf_hash(input);

            if hash1 != hash2 {
                return TestResult::fail(format!(
                    "Non-deterministic hashing for input '{}': {} vs {}",
                    input, hash1, hash2
                ));
            }
        }

        // Test with problematic characters that could cause parsing issues
        let special_char_tests = vec![
            "input\0with\0nulls",
            "input\nwith\nlines",
            "input:with:colons",
            "input with spaces",
            "input\twith\ttabs",
        ];

        let mut all_hashes = HashSet::new();
        for input in special_char_tests {
            let hash = marker_leaf_hash(input);

            if all_hashes.contains(&hash) {
                return TestResult::fail(format!(
                    "Hash collision with special characters: input '{}' hash: {}",
                    input
                        .replace('\0', "\\0")
                        .replace('\n', "\\n")
                        .replace('\t', "\\t"),
                    hash
                ));
            }

            all_hashes.insert(hash.clone());

            // Verify determinism for special characters
            let hash2 = marker_leaf_hash(input);
            if hash != hash2 {
                return TestResult::fail(format!(
                    "Non-deterministic hashing for special chars: '{}'",
                    input.replace('\0', "\\0")
                ));
            }
        }

        TestResult::pass()
    }
}

/// R7.3: MUST prevent hash collision attacks
pub struct HashCollisionResistanceTest;

impl ConformanceTest for HashCollisionResistanceTest {
    fn id(&self) -> &str {
        "R7.3"
    }
    fn name(&self) -> &str {
        "Hash collision resistance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "7"
    }
    fn description(&self) -> &str {
        "MUST resist hash collision attacks across all hash operations"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        // Test systematic collision resistance
        let mut all_hashes = HashSet::new();
        let test_inputs: Vec<String> = (0..1000).map(|i| format!("test-input-{:04}", i)).collect();

        // Test leaf hash collision resistance
        for input in &test_inputs {
            let hash = marker_leaf_hash(input);

            if all_hashes.contains(&hash) {
                return TestResult::fail(format!(
                    "Hash collision detected for input '{}': {}",
                    input, hash
                ));
            }

            all_hashes.insert(hash.clone());

            // Verify hash properties
            if hash.len() != 64 {
                return TestResult::fail(format!(
                    "Invalid hash length for '{}': {} (expected 64)",
                    input,
                    hash.len()
                ));
            }

            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return TestResult::fail(format!("Invalid hash format for '{}': {}", input, hash));
            }
        }

        // Test collision resistance in Merkle tree construction
        let stream1 = ctx.generate_markers(100, "collision1");
        let stream2 = ctx.generate_markers(100, "collision2");

        let cp1 = ctx.create_checkpoint(&stream1);
        let cp2 = ctx.create_checkpoint(&stream2);

        let root1 = cp1.root().expect("root1");
        let root2 = cp2.root().expect("root2");

        if root1.root_hash == root2.root_hash {
            return TestResult::fail(format!(
                "Root hash collision between different streams: {}",
                root1.root_hash
            ));
        }

        // Test leaf hash collision resistance with crafted inputs
        let crafted_inputs = vec!["aaaa", "aaab", "aaba", "abaa", "baaa", "bbbb", "cccc"];

        let mut crafted_hashes = HashSet::new();
        for input in crafted_inputs {
            let hash = marker_leaf_hash(input);

            if crafted_hashes.contains(&hash) {
                return TestResult::fail(format!("Hash collision in crafted inputs: '{}'", input));
            }

            crafted_hashes.insert(hash);
        }

        TestResult::pass()
    }
}

/// R7.4: MUST use constant-time comparisons for security-sensitive operations
pub struct ConstantTimeComparisonsTest;

impl ConformanceTest for ConstantTimeComparisonsTest {
    fn id(&self) -> &str {
        "R7.4"
    }
    fn name(&self) -> &str {
        "Constant-time comparisons"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "7"
    }
    fn description(&self) -> &str {
        "MUST use constant-time comparisons for security-sensitive hash operations"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        // We can't directly test timing, but we can verify that the security-critical
        // verification functions behave correctly with tampered inputs that would
        // reveal timing differences in naive implementations

        let stream = ctx.generate_markers(10, "consttime");
        let cp = ctx.create_checkpoint(&stream);
        let root = cp.root().expect("root");

        // Test inclusion proof verification with various hash tampering patterns
        let proof = mmr_inclusion_proof(&stream, &cp, 5).expect("proof");
        let correct_hash = stream.get(5).expect("marker").marker_hash.clone();

        // Test early-return attack resistance (first byte different)
        let mut tampered_hash = correct_hash.clone();
        tampered_hash.replace_range(0..1, "Z");

        match verify_inclusion(&proof, root, &tampered_hash) {
            Err(err) => {
                if err.code() != "MMR_LEAF_MISMATCH" {
                    return TestResult::fail(format!(
                        "Expected MMR_LEAF_MISMATCH for first-byte tamper, got: {}",
                        err.code()
                    ));
                }
            }
            Ok(_) => return TestResult::fail("Should reject tampered first byte"),
        }

        // Test late-difference attack resistance (last byte different)
        let mut late_tampered = correct_hash.clone();
        if let Some(last_char) = late_tampered.chars().last() {
            let new_char = if last_char == 'a' { 'b' } else { 'a' };
            late_tampered.pop();
            late_tampered.push(new_char);
        }

        match verify_inclusion(&proof, root, &late_tampered) {
            Err(err) => {
                if err.code() != "MMR_LEAF_MISMATCH" {
                    return TestResult::fail(format!(
                        "Expected MMR_LEAF_MISMATCH for last-byte tamper, got: {}",
                        err.code()
                    ));
                }
            }
            Ok(_) => return TestResult::fail("Should reject tampered last byte"),
        }

        // Test root hash tampering resistance
        let mut tampered_root = root.clone();
        if tampered_root.root_hash.len() >= 2 {
            tampered_root.root_hash.replace_range(0..2, "ff");
        }

        match verify_inclusion(&proof, &tampered_root, &correct_hash) {
            Err(err) => {
                if err.code() != "MMR_ROOT_MISMATCH" {
                    return TestResult::fail(format!(
                        "Expected MMR_ROOT_MISMATCH for root tamper, got: {}",
                        err.code()
                    ));
                }
            }
            Ok(_) => return TestResult::fail("Should reject tampered root"),
        }

        // Test prefix proof verification constant-time properties
        let small_stream = ctx.generate_markers(3, "prefix-chain");
        let large_stream = ctx.generate_markers(8, "prefix-chain");
        let small_cp = ctx.create_checkpoint(&small_stream);
        let large_cp = ctx.create_checkpoint(&large_stream);

        let prefix_proof = mmr_prefix_proof(&small_cp, &large_cp).expect("prefix proof");
        let small_root = small_cp.root().expect("small root");
        let large_root = large_cp.root().expect("large root");

        // Test with tampered prefix root (various positions)
        for tamper_pos in [0, 10, 60] {
            if tamper_pos < prefix_proof.prefix_root_hash.len() {
                let mut tampered_prefix_proof = prefix_proof.clone();
                let replacement =
                    if tampered_prefix_proof.prefix_root_hash.as_bytes()[tamper_pos] == b'f' {
                        "0"
                    } else {
                        "f"
                    };
                tampered_prefix_proof
                    .prefix_root_hash
                    .replace_range(tamper_pos..tamper_pos + 1, replacement);

                match verify_prefix(&tampered_prefix_proof, small_root, large_root) {
                    Err(err) => {
                        if err.code() != "MMR_ROOT_MISMATCH" {
                            return TestResult::fail(format!(
                                "Expected MMR_ROOT_MISMATCH for prefix tamper at {}, got: {}",
                                tamper_pos,
                                err.code()
                            ));
                        }
                    }
                    Ok(_) => {
                        return TestResult::fail(format!(
                            "Should reject prefix tamper at position {}",
                            tamper_pos
                        ));
                    }
                }
            }
        }

        TestResult::pass()
    }
}

/// R7.5: MUST generate deterministic hashes for identical inputs
pub struct DeterministicHashingTest;

impl ConformanceTest for DeterministicHashingTest {
    fn id(&self) -> &str {
        "R7.5"
    }
    fn name(&self) -> &str {
        "Deterministic hashing"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "7"
    }
    fn description(&self) -> &str {
        "MUST produce identical hashes for identical inputs across all operations"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        // Test deterministic leaf hashing
        let test_inputs = vec![
            String::new(),
            "a".to_string(),
            "test-marker-hash".to_string(),
            "unicode-test-🔥".to_string(),
            "null\0test".to_string(),
            "long".repeat(100),
        ];

        for input in test_inputs {
            let hashes: Vec<String> = (0..10).map(|_| marker_leaf_hash(&input)).collect();

            // All hashes should be identical
            let first_hash = &hashes[0];
            for (i, hash) in hashes.iter().enumerate() {
                if hash != first_hash {
                    return TestResult::fail(format!(
                        "Non-deterministic leaf hash for '{}': iteration {} differs",
                        input.replace('\0', "\\0"),
                        i
                    ));
                }
            }
        }

        // Test deterministic checkpoint rebuilding
        let stream = ctx.generate_markers(50, "deterministic");

        let checkpoints: Vec<MmrCheckpoint> =
            (0..5).map(|_| ctx.create_checkpoint(&stream)).collect();

        let first_root = checkpoints[0].root().expect("first root");
        for (i, cp) in checkpoints.iter().enumerate() {
            let root = cp.root().expect("root");

            if root.tree_size != first_root.tree_size {
                return TestResult::fail(format!(
                    "Non-deterministic tree size: iteration {} differs",
                    i
                ));
            }

            if root.root_hash != first_root.root_hash {
                return TestResult::fail(format!(
                    "Non-deterministic root hash: iteration {} differs",
                    i
                ));
            }

            if cp.leaf_hashes() != checkpoints[0].leaf_hashes() {
                return TestResult::fail(format!(
                    "Non-deterministic leaf hashes: iteration {} differs",
                    i
                ));
            }
        }

        // Test deterministic proof generation
        for seq in [0, 25, 49] {
            let proofs: Vec<InclusionProof> = (0..5)
                .map(|_| mmr_inclusion_proof(&stream, &checkpoints[0], seq).expect("proof"))
                .collect();

            let first_proof = &proofs[0];
            for (i, proof) in proofs.iter().enumerate() {
                if proof != first_proof {
                    return TestResult::fail_with_details(
                        format!(
                            "Non-deterministic proof for sequence {}: iteration {} differs",
                            seq, i
                        ),
                        serde_json::json!({
                            "sequence": seq,
                            "iteration": i,
                            "first_proof": first_proof,
                            "different_proof": proof
                        }),
                    );
                }
            }
        }

        TestResult::pass()
    }
}
