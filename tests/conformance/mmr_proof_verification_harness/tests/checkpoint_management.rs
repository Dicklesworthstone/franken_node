//! Checkpoint Management conformance tests (R1.*).

use super::super::*;

/// R1.1: MUST maintain enabled/disabled state
pub struct CheckpointEnabledDisabledTest;

impl ConformanceTest for CheckpointEnabledDisabledTest {
    fn id(&self) -> &str {
        "R1.1"
    }
    fn name(&self) -> &str {
        "Checkpoint enabled/disabled state management"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "1"
    }
    fn description(&self) -> &str {
        "Checkpoint MUST correctly maintain and report enabled/disabled state"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Test enabled checkpoint
        let enabled_cp = MmrCheckpoint::enabled();
        if !enabled_cp.is_enabled() {
            return TestResult::fail("Enabled checkpoint reports disabled state");
        }

        // Test disabled checkpoint
        let disabled_cp = MmrCheckpoint::disabled();
        if disabled_cp.is_enabled() {
            return TestResult::fail("Disabled checkpoint reports enabled state");
        }

        // Test state mutation
        let mut mutable_cp = MmrCheckpoint::enabled();
        mutable_cp.set_enabled(false);
        if mutable_cp.is_enabled() {
            return TestResult::fail("Failed to disable checkpoint");
        }

        mutable_cp.set_enabled(true);
        if !mutable_cp.is_enabled() {
            return TestResult::fail("Failed to re-enable checkpoint");
        }

        TestResult::pass()
    }
}

/// R1.2: MUST fail closed when disabled (reject all operations)
pub struct CheckpointFailClosedTest;

impl ConformanceTest for CheckpointFailClosedTest {
    fn id(&self) -> &str {
        "R1.2"
    }
    fn name(&self) -> &str {
        "Checkpoint fail-closed when disabled"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "1"
    }
    fn description(&self) -> &str {
        "Disabled checkpoint MUST fail closed and reject all operations"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let mut disabled_cp = MmrCheckpoint::disabled();
        let stream = ctx.generate_markers(5, "failclosed");

        // Test append_marker_hash fails
        let first_marker = stream.get(0).expect("first marker");
        match disabled_cp.append_marker_hash(&first_marker.marker_hash) {
            Err(err) => {
                if err.code() != "MMR_DISABLED" {
                    return TestResult::fail(format!("Expected MMR_DISABLED, got: {}", err.code()));
                }
            }
            Ok(_) => return TestResult::fail("append_marker_hash should fail when disabled"),
        }

        // Test rebuild_from_stream fails
        match disabled_cp.rebuild_from_stream(&stream) {
            Err(err) => {
                if err.code() != "MMR_DISABLED" {
                    return TestResult::fail(format!("Expected MMR_DISABLED, got: {}", err.code()));
                }
            }
            Ok(_) => return TestResult::fail("rebuild_from_stream should fail when disabled"),
        }

        // Test sync_from_stream fails
        match disabled_cp.sync_from_stream(&stream) {
            Err(err) => {
                if err.code() != "MMR_DISABLED" {
                    return TestResult::fail(format!("Expected MMR_DISABLED, got: {}", err.code()));
                }
            }
            Ok(_) => return TestResult::fail("sync_from_stream should fail when disabled"),
        }

        // Test inclusion proof generation fails
        match mmr_inclusion_proof(&stream, &disabled_cp, 0) {
            Err(err) => {
                if err.code() != "MMR_DISABLED" {
                    return TestResult::fail(format!("Expected MMR_DISABLED, got: {}", err.code()));
                }
            }
            Ok(_) => return TestResult::fail("inclusion proof should fail when disabled"),
        }

        // Test prefix proof generation fails
        let enabled_cp = ctx.create_checkpoint(&stream);
        match mmr_prefix_proof(&disabled_cp, &enabled_cp) {
            Err(err) => {
                if err.code() != "MMR_DISABLED" {
                    return TestResult::fail(format!("Expected MMR_DISABLED, got: {}", err.code()));
                }
            }
            Ok(_) => return TestResult::fail("prefix proof should fail when disabled"),
        }

        // Verify checkpoint state remains unchanged
        if disabled_cp.tree_size() != 0 {
            return TestResult::fail("Disabled checkpoint tree size should remain 0");
        }
        if disabled_cp.root().is_some() {
            return TestResult::fail("Disabled checkpoint should have no root");
        }

        TestResult::pass()
    }
}

/// R1.3: MUST rebuild deterministically from marker streams
pub struct CheckpointDeterministicRebuildTest;

impl ConformanceTest for CheckpointDeterministicRebuildTest {
    fn id(&self) -> &str {
        "R1.3"
    }
    fn name(&self) -> &str {
        "Deterministic checkpoint rebuild"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "1"
    }
    fn description(&self) -> &str {
        "Checkpoint rebuild MUST be deterministic for identical marker streams"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let stream = ctx.generate_markers(20, "deterministic");

        // Build checkpoint multiple times
        let cp1 = ctx.create_checkpoint(&stream);
        let cp2 = ctx.create_checkpoint(&stream);

        // Verify identical results
        let root1 = cp1.root().expect("root1");
        let root2 = cp2.root().expect("root2");

        if root1.tree_size != root2.tree_size {
            return TestResult::fail(format!(
                "Tree size mismatch: {} vs {}",
                root1.tree_size, root2.tree_size
            ));
        }

        if root1.root_hash != root2.root_hash {
            return TestResult::fail(format!(
                "Root hash mismatch: {} vs {}",
                root1.root_hash, root2.root_hash
            ));
        }

        if cp1.leaf_hashes() != cp2.leaf_hashes() {
            return TestResult::fail("Leaf hashes differ between rebuilds");
        }

        // Test rebuild after state mutation
        let mut cp3 = MmrCheckpoint::enabled();
        cp3.set_enabled(false);
        cp3.set_enabled(true);
        cp3.rebuild_from_stream(&stream).expect("rebuild");

        let root3 = cp3.root().expect("root3");
        if root1.root_hash != root3.root_hash {
            return TestResult::fail("Root hash differs after state mutation");
        }

        TestResult::pass()
    }
}

/// R1.4: MUST maintain capacity limit (4096 leaf hashes max)
pub struct CheckpointCapacityLimitTest;

impl ConformanceTest for CheckpointCapacityLimitTest {
    fn id(&self) -> &str {
        "R1.4"
    }
    fn name(&self) -> &str {
        "Checkpoint capacity limit enforcement"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "1"
    }
    fn description(&self) -> &str {
        "Checkpoint MUST enforce maximum capacity of 4096 leaf hashes"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        // Test with exactly the capacity limit
        let capacity_stream = ctx.generate_markers(4096, "capacity");
        let cp = ctx.create_checkpoint(&capacity_stream);

        if cp.tree_size() != 4096 {
            return TestResult::fail(format!("Tree size should be 4096, got: {}", cp.tree_size()));
        }

        if cp.leaf_hashes().len() != 4096 {
            return TestResult::fail(format!(
                "Leaf hashes length should be 4096, got: {}",
                cp.leaf_hashes().len()
            ));
        }

        TestResult::pass()
    }
}

/// R1.5: MUST evict oldest entries when capacity exceeded
pub struct CheckpointEvictionTest;

impl ConformanceTest for CheckpointEvictionTest {
    fn id(&self) -> &str {
        "R1.5"
    }
    fn name(&self) -> &str {
        "Checkpoint eviction policy"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "1"
    }
    fn description(&self) -> &str {
        "Checkpoint MUST evict oldest entries when capacity is exceeded"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        // Create stream exceeding capacity
        let oversized_stream = ctx.generate_markers(4100, "eviction");
        let cp = ctx.create_checkpoint(&oversized_stream);

        // Verify capacity enforcement
        if cp.leaf_hashes().len() != 4096 {
            return TestResult::fail(format!(
                "Leaf hashes should be limited to 4096, got: {}",
                cp.leaf_hashes().len()
            ));
        }

        // Verify retention window moved (oldest entries evicted)
        if let Some(first_marker) = oversized_stream.first() {
            if first_marker.sequence != 4 {
                return TestResult::fail(format!(
                    "Expected first retained sequence 4, got: {}",
                    first_marker.sequence
                ));
            }
        } else {
            return TestResult::fail("Stream should have first marker after eviction");
        }

        // Verify evicted sequences are no longer accessible for proofs
        match mmr_inclusion_proof(&oversized_stream, &cp, 0) {
            Err(err) => {
                if err.code() != "MMR_SEQUENCE_OUT_OF_RANGE" {
                    return TestResult::fail(format!(
                        "Expected MMR_SEQUENCE_OUT_OF_RANGE for evicted sequence, got: {}",
                        err.code()
                    ));
                }
            }
            Ok(_) => return TestResult::fail("Should not generate proof for evicted sequence"),
        }

        TestResult::pass()
    }
}

/// R1.6: MUST preserve tree_size across rebuilds
pub struct CheckpointTreeSizePreservationTest;

impl ConformanceTest for CheckpointTreeSizePreservationTest {
    fn id(&self) -> &str {
        "R1.6"
    }
    fn name(&self) -> &str {
        "Tree size preservation across rebuilds"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "1"
    }
    fn description(&self) -> &str {
        "Checkpoint MUST preserve tree_size consistently across rebuilds"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let stream = ctx.generate_markers(50, "treesize");

        // Initial build
        let mut cp = MmrCheckpoint::enabled();
        cp.rebuild_from_stream(&stream).expect("initial build");
        let initial_size = cp.tree_size();

        if initial_size != 50 {
            return TestResult::fail(format!(
                "Initial tree size should be 50, got: {}",
                initial_size
            ));
        }

        // Rebuild multiple times
        for i in 0..5 {
            if let Err(err) = cp.rebuild_from_stream(&stream) {
                return TestResult::fail(format!("Rebuild {} failed: {}", i, err));
            }

            if cp.tree_size() != initial_size {
                return TestResult::fail(format!(
                    "Tree size changed during rebuild {}: {} -> {}",
                    i,
                    initial_size,
                    cp.tree_size()
                ));
            }
        }

        // Test sync_from_stream preserves size
        cp.sync_from_stream(&stream).expect("sync");
        if cp.tree_size() != initial_size {
            return TestResult::fail(format!(
                "Tree size changed during sync: {} -> {}",
                initial_size,
                cp.tree_size()
            ));
        }

        TestResult::pass()
    }
}
