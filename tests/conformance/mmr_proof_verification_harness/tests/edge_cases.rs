//! Edge Case conformance tests.

use super::super::*;

fn single_marker_checkpoint(ctx: &TestContext) -> (MarkerStream, MmrCheckpoint) {
    let stream = ctx.generate_markers(1, "single-marker");
    let checkpoint = ctx.create_checkpoint(&stream);
    (stream, checkpoint)
}

macro_rules! should_placeholder_test {
    ($struct_name:ident, $id:expr, $name:expr, $category:expr, $level:expr, $section:expr, $desc:expr) => {
        pub struct $struct_name;
        impl ConformanceTest for $struct_name {
            fn id(&self) -> &str {
                $id
            }
            fn name(&self) -> &str {
                $name
            }
            fn category(&self) -> TestCategory {
                $category
            }
            fn requirement_level(&self) -> RequirementLevel {
                $level
            }
            fn spec_section(&self) -> &str {
                $section
            }
            fn description(&self) -> &str {
                $desc
            }
            fn run(&self, _ctx: &TestContext) -> TestResult {
                TestResult::skipped("Implementation pending")
            }
        }
    };
}

pub struct EmptyStreamTest;

impl ConformanceTest for EmptyStreamTest {
    fn id(&self) -> &str {
        "E1"
    }
    fn name(&self) -> &str {
        "Empty stream handling"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "Edge"
    }
    fn description(&self) -> &str {
        "MUST handle empty streams gracefully"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let stream = MarkerStream::new();
        let mut checkpoint = MmrCheckpoint::enabled();
        match checkpoint.rebuild_from_stream(&stream) {
            Err(err) if err.code() == "MMR_EMPTY_CHECKPOINT" => {}
            Err(err) => return TestResult::fail(format!("unexpected rebuild error: {err}")),
            Ok(_) => return TestResult::fail("empty stream produced a checkpoint root"),
        }

        match mmr_inclusion_proof(&stream, &checkpoint, 0) {
            Err(err) if err.code() == "MMR_EMPTY_CHECKPOINT" => {}
            Err(err) => return TestResult::fail(format!("unexpected inclusion error: {err}")),
            Ok(_) => return TestResult::fail("empty stream produced an inclusion proof"),
        }

        let empty_proof = InclusionProof {
            leaf_index: 0,
            tree_size: 0,
            leaf_hash: marker_leaf_hash("empty"),
            audit_path: Vec::new(),
        };
        let empty_root = MmrRoot {
            tree_size: 0,
            root_hash: marker_leaf_hash("empty-root"),
        };
        match verify_inclusion(&empty_proof, &empty_root, &"empty".to_string()) {
            Err(err) if err.code() == "MMR_EMPTY_CHECKPOINT" => TestResult::pass(),
            Err(err) => TestResult::fail(format!("unexpected verify error: {err}")),
            Ok(()) => TestResult::fail("zero-sized proof verified successfully"),
        }
    }
}

pub struct SingleMarkerTest;

impl ConformanceTest for SingleMarkerTest {
    fn id(&self) -> &str {
        "E2"
    }
    fn name(&self) -> &str {
        "Single marker stream"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "Edge"
    }
    fn description(&self) -> &str {
        "MUST handle single-marker streams"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (stream, checkpoint) = single_marker_checkpoint(ctx);
        let root = checkpoint.root().expect("single-marker root");
        if root.tree_size != 1 || checkpoint.tree_size() != 1 {
            return TestResult::fail(format!(
                "single-marker checkpoint has root tree_size={} checkpoint tree_size={}",
                root.tree_size,
                checkpoint.tree_size()
            ));
        }

        let marker = stream.get(0).expect("single marker");
        let proof = match mmr_inclusion_proof(&stream, &checkpoint, 0) {
            Ok(proof) => proof,
            Err(err) => return TestResult::fail(format!("single-marker proof failed: {err}")),
        };
        if proof.leaf_index != 0 || proof.tree_size != 1 || !proof.audit_path.is_empty() {
            return TestResult::fail(format!("unexpected single-marker proof shape: {proof:?}"));
        }
        if proof.leaf_hash != marker_leaf_hash(&marker.marker_hash) {
            return TestResult::fail("single-marker proof leaf hash mismatch");
        }

        match verify_inclusion(&proof, root, &marker.marker_hash) {
            Ok(()) => TestResult::pass(),
            Err(err) => TestResult::fail(format!("single-marker proof did not verify: {err}")),
        }
    }
}

should_placeholder_test!(
    UnicodeHandlingTest,
    "E3",
    "Unicode marker handling",
    TestCategory::EdgeCase,
    RequirementLevel::Should,
    "Edge",
    "SHOULD handle Unicode markers correctly"
);
should_placeholder_test!(
    ExtremeValuesTest,
    "E4",
    "Extreme value handling",
    TestCategory::EdgeCase,
    RequirementLevel::Should,
    "Edge",
    "SHOULD handle extreme numeric values"
);
