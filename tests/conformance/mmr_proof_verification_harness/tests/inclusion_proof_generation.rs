//! Inclusion Proof Generation conformance tests (R2.*).

use super::super::*;

/// R2.1: MUST generate valid inclusion proofs for retained sequences
pub struct InclusionProofValidGenerationTest;

impl ConformanceTest for InclusionProofValidGenerationTest {
    fn id(&self) -> &str {
        "R2.1"
    }
    fn name(&self) -> &str {
        "Valid inclusion proof generation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "2"
    }
    fn description(&self) -> &str {
        "MUST generate valid inclusion proofs for all retained sequence numbers"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let stream = ctx.generate_markers(10, "valid");
        let cp = ctx.create_checkpoint(&stream);
        let root = cp.root().expect("checkpoint root");

        // Test proof generation for boundary sequences
        let test_sequences = vec![0, 4, 9]; // first, middle, last

        for seq in test_sequences {
            let proof = match mmr_inclusion_proof(&stream, &cp, seq) {
                Ok(p) => p,
                Err(e) => {
                    return TestResult::fail(format!(
                        "Failed to generate proof for sequence {}: {}",
                        seq, e
                    ));
                }
            };

            // Verify proof structure
            let result = comparison::assert_proof_valid(&proof);
            if !result.is_passing() {
                return TestResult::fail(format!(
                    "Invalid proof structure for sequence {}: {}",
                    seq, result
                ));
            }

            // Verify proof verifies successfully
            let marker = stream.get(seq).expect("marker");
            if let Err(e) = verify_inclusion(&proof, root, &marker.marker_hash) {
                return TestResult::fail(format!(
                    "Generated proof for sequence {} failed verification: {}",
                    seq, e
                ));
            }

            // Verify proof fields are consistent
            if proof.tree_size != root.tree_size {
                return TestResult::fail(format!(
                    "Proof tree size {} doesn't match root tree size {}",
                    proof.tree_size, root.tree_size
                ));
            }

            if proof.leaf_hash != marker_leaf_hash(&marker.marker_hash) {
                return TestResult::fail(format!(
                    "Proof leaf hash doesn't match expected marker hash for sequence {}",
                    seq
                ));
            }
        }

        TestResult::pass()
    }
}

/// R2.2: MUST reject requests for evicted sequences
pub struct InclusionProofEvictedSequenceTest;

impl ConformanceTest for InclusionProofEvictedSequenceTest {
    fn id(&self) -> &str {
        "R2.2"
    }
    fn name(&self) -> &str {
        "Evicted sequence rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "2"
    }
    fn description(&self) -> &str {
        "MUST reject inclusion proof requests for evicted sequences"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        // Create oversized stream to trigger eviction
        let oversized_stream = ctx.generate_markers(4100, "evicted");
        let cp = ctx.create_checkpoint(&oversized_stream);

        // Try to generate proof for evicted sequence
        match mmr_inclusion_proof(&oversized_stream, &cp, 0) {
            Err(err) => {
                let result = comparison::assert_error_code("MMR_SEQUENCE_OUT_OF_RANGE", &err);
                if !result.is_passing() {
                    return result;
                }
            }
            Ok(_) => return TestResult::fail("Should not generate proof for evicted sequence 0"),
        }

        // Verify first retained sequence is accessible
        if let Some(first_marker) = oversized_stream.first() {
            let first_seq = first_marker.sequence;
            match mmr_inclusion_proof(&oversized_stream, &cp, first_seq) {
                Ok(_) => {} // Expected to succeed
                Err(e) => {
                    return TestResult::fail(format!(
                        "Should generate proof for first retained sequence {}: {}",
                        first_seq, e
                    ));
                }
            }
        }

        TestResult::pass()
    }
}

/// R2.3: MUST reject requests for out-of-range sequences
pub struct InclusionProofOutOfRangeTest;

impl ConformanceTest for InclusionProofOutOfRangeTest {
    fn id(&self) -> &str {
        "R2.3"
    }
    fn name(&self) -> &str {
        "Out-of-range sequence rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "2"
    }
    fn description(&self) -> &str {
        "MUST reject inclusion proof requests for out-of-range sequences"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let stream = ctx.generate_markers(5, "outofrange");
        let cp = ctx.create_checkpoint(&stream);

        // Test sequence beyond stream length
        match mmr_inclusion_proof(&stream, &cp, 10) {
            Err(err) => {
                let result = comparison::assert_error_code("MMR_SEQUENCE_OUT_OF_RANGE", &err);
                if !result.is_passing() {
                    return result;
                }
            }
            Ok(_) => {
                return TestResult::fail(
                    "Should not generate proof for sequence 10 in 5-element stream",
                );
            }
        }

        // Test sequence at stream length (boundary case)
        match mmr_inclusion_proof(&stream, &cp, 5) {
            Err(err) => {
                let result = comparison::assert_error_code("MMR_SEQUENCE_OUT_OF_RANGE", &err);
                if !result.is_passing() {
                    return result;
                }
            }
            Ok(_) => {
                return TestResult::fail("Should not generate proof for sequence at stream length");
            }
        }

        // Verify valid sequence still works
        match mmr_inclusion_proof(&stream, &cp, 4) {
            Ok(_) => {} // Expected
            Err(e) => return TestResult::fail(format!("Valid sequence 4 should work: {}", e)),
        }

        TestResult::pass()
    }
}

/// R2.4: MUST reject requests when checkpoint is stale
pub struct InclusionProofStaleCheckpointTest;

impl ConformanceTest for InclusionProofStaleCheckpointTest {
    fn id(&self) -> &str {
        "R2.4"
    }
    fn name(&self) -> &str {
        "Stale checkpoint rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "2"
    }
    fn description(&self) -> &str {
        "MUST reject inclusion proof requests when checkpoint is stale"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let stream = ctx.generate_markers(5, "stale");

        // Create checkpoint from partial stream
        let partial_stream = ctx.generate_markers(3, "stale");
        let stale_cp = ctx.create_checkpoint(&partial_stream);

        // Try to generate proof using stale checkpoint with full stream
        match mmr_inclusion_proof(&stream, &stale_cp, 0) {
            Err(err) => {
                let result = comparison::assert_error_code("MMR_CHECKPOINT_STALE", &err);
                if !result.is_passing() {
                    return result;
                }
            }
            Ok(_) => return TestResult::fail("Should not generate proof with stale checkpoint"),
        }

        // Test checkpoint with modified marker (same length, different content)
        let mut modified_cp = MmrCheckpoint::enabled();
        modified_cp
            .append_marker_hash("different-hash")
            .expect("append");

        let single_stream = ctx.generate_markers(1, "single");

        match mmr_inclusion_proof(&single_stream, &modified_cp, 0) {
            Err(err) => {
                let result = comparison::assert_error_code("MMR_CHECKPOINT_STALE", &err);
                if !result.is_passing() {
                    return result;
                }
            }
            Ok(_) => return TestResult::fail("Should not generate proof with modified checkpoint"),
        }

        TestResult::pass()
    }
}

/// R2.5: MUST reject requests when checkpoint is disabled
pub struct InclusionProofDisabledTest;

impl ConformanceTest for InclusionProofDisabledTest {
    fn id(&self) -> &str {
        "R2.5"
    }
    fn name(&self) -> &str {
        "Disabled checkpoint rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "2"
    }
    fn description(&self) -> &str {
        "MUST reject inclusion proof requests when checkpoint is disabled"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let stream = ctx.generate_markers(3, "disabled");
        let disabled_cp = MmrCheckpoint::disabled();

        match mmr_inclusion_proof(&stream, &disabled_cp, 0) {
            Err(err) => {
                let result = comparison::assert_error_code("MMR_DISABLED", &err);
                if !result.is_passing() {
                    return result;
                }
            }
            Ok(_) => return TestResult::fail("Should not generate proof with disabled checkpoint"),
        }

        TestResult::pass()
    }
}

/// R2.6: MUST generate deterministic proofs for identical inputs
pub struct InclusionProofDeterministicTest;

impl ConformanceTest for InclusionProofDeterministicTest {
    fn id(&self) -> &str {
        "R2.6"
    }
    fn name(&self) -> &str {
        "Deterministic proof generation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "2"
    }
    fn description(&self) -> &str {
        "MUST generate identical proofs for identical inputs"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let stream = ctx.generate_markers(15, "deterministic");
        let cp = ctx.create_checkpoint(&stream);

        let test_sequences = vec![0, 7, 14];

        for seq in test_sequences {
            // Generate proof multiple times
            let proof1 = match mmr_inclusion_proof(&stream, &cp, seq) {
                Ok(proof) => proof,
                Err(e) => {
                    return TestResult::fail(format!("Failed to generate proof1: {}", e));
                }
            };
            let proof2 = match mmr_inclusion_proof(&stream, &cp, seq) {
                Ok(proof) => proof,
                Err(e) => {
                    return TestResult::fail(format!("Failed to generate proof2: {}", e));
                }
            };

            // Verify complete equality
            if proof1 != proof2 {
                return TestResult::fail_with_details(
                    format!("Non-deterministic proof generation for sequence {}", seq),
                    serde_json::json!({
                        "sequence": seq,
                        "proof1": proof1,
                        "proof2": proof2
                    }),
                );
            }

            // Verify individual fields match
            if proof1.leaf_index != proof2.leaf_index {
                return TestResult::fail(format!(
                    "Leaf index mismatch for sequence {}: {} vs {}",
                    seq, proof1.leaf_index, proof2.leaf_index
                ));
            }

            if proof1.tree_size != proof2.tree_size {
                return TestResult::fail(format!(
                    "Tree size mismatch for sequence {}: {} vs {}",
                    seq, proof1.tree_size, proof2.tree_size
                ));
            }

            if proof1.leaf_hash != proof2.leaf_hash {
                return TestResult::fail(format!(
                    "Leaf hash mismatch for sequence {}: {} vs {}",
                    seq, proof1.leaf_hash, proof2.leaf_hash
                ));
            }

            if proof1.audit_path != proof2.audit_path {
                return TestResult::fail(format!(
                    "Audit path mismatch for sequence {}: {:?} vs {:?}",
                    seq, proof1.audit_path, proof2.audit_path
                ));
            }
        }

        TestResult::pass()
    }
}

/// R2.7: MUST limit audit path length to log(tree_size)
pub struct InclusionProofAuditPathLengthTest;

impl ConformanceTest for InclusionProofAuditPathLengthTest {
    fn id(&self) -> &str {
        "R2.7"
    }
    fn name(&self) -> &str {
        "Audit path length limit"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Performance
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "2"
    }
    fn description(&self) -> &str {
        "MUST limit audit path length to logarithmic bound"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let test_cases = vec![
            (1, 0),     // Single element
            (2, 1),     // Two elements
            (15, 4),    // Mid-size
            (1000, 10), // Large tree
            (4000, 12), // Near capacity limit
        ];

        for (tree_size, expected_max_path) in test_cases {
            let stream = ctx.generate_markers(tree_size, "pathlen");
            let cp = ctx.create_checkpoint(&stream);

            // Test proof for last element (typically longest path)
            let last_seq = tree_size - 1;
            let proof = match mmr_inclusion_proof(&stream, &cp, last_seq) {
                Ok(proof) => proof,
                Err(e) => {
                    return TestResult::fail(format!("Failed to generate proof: {}", e));
                }
            };

            if proof.audit_path.len() > expected_max_path {
                return TestResult::fail(format!(
                    "Audit path too long for tree size {}: {} > {} (expected max)",
                    tree_size,
                    proof.audit_path.len(),
                    expected_max_path
                ));
            }

            // Verify the logarithmic bound holds
            let computed_bound = if tree_size <= 1 {
                0
            } else {
                (64 - (tree_size - 1).leading_zeros()) as usize
            };

            if proof.audit_path.len() > computed_bound.min(64) {
                return TestResult::fail(format!(
                    "Audit path exceeds computed logarithmic bound for tree size {}: {} > {}",
                    tree_size,
                    proof.audit_path.len(),
                    computed_bound
                ));
            }
        }

        TestResult::pass()
    }
}
