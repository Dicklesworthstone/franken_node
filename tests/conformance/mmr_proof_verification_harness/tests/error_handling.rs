//! Error Handling conformance tests (R6.*).

use super::super::*;

fn expect_error_code<T>(result: Result<T, ProofError>, expected_code: &str) -> Option<TestResult> {
    match result {
        Err(err) if err.code() == expected_code => None,
        Err(err) => Some(TestResult::fail(format!(
            "expected {expected_code}, got {} ({err})",
            err.code()
        ))),
        Ok(_) => Some(TestResult::fail(format!(
            "operation succeeded; expected {expected_code}"
        ))),
    }
}

pub struct ErrorCodeSpecificityTest;

impl ConformanceTest for ErrorCodeSpecificityTest {
    fn id(&self) -> &str {
        "R6.1"
    }
    fn name(&self) -> &str {
        "Error code specificity"
    }
    fn category(&self) -> TestCategory {
        TestCategory::ErrorHandling
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "6"
    }
    fn description(&self) -> &str {
        "MUST return specific error codes"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let cases = [
            (ProofError::MmrDisabled, "MMR_DISABLED"),
            (ProofError::EmptyCheckpoint, "MMR_EMPTY_CHECKPOINT"),
            (
                ProofError::SequenceOutOfRange {
                    sequence: 7,
                    tree_size: 3,
                },
                "MMR_SEQUENCE_OUT_OF_RANGE",
            ),
            (
                ProofError::CheckpointStale {
                    checkpoint_tree_size: 3,
                    stream_tree_size: 7,
                },
                "MMR_CHECKPOINT_STALE",
            ),
            (
                ProofError::PrefixSizeInvalid {
                    prefix_size: 8,
                    super_tree_size: 4,
                },
                "MMR_PREFIX_SIZE_INVALID",
            ),
            (
                ProofError::InvalidProof {
                    reason: "bad proof".to_string(),
                },
                "MMR_INVALID_PROOF",
            ),
            (
                ProofError::LeafMismatch {
                    expected: marker_leaf_hash("expected"),
                    actual: marker_leaf_hash("actual"),
                },
                "MMR_LEAF_MISMATCH",
            ),
            (
                ProofError::RootMismatch {
                    expected: marker_leaf_hash("expected-root"),
                    actual: marker_leaf_hash("actual-root"),
                },
                "MMR_ROOT_MISMATCH",
            ),
        ];

        let mut seen_codes = std::collections::HashSet::new();
        for (err, expected_code) in cases {
            if err.code() != expected_code {
                return TestResult::fail(format!(
                    "error {err:?} produced code {}, expected {expected_code}",
                    err.code()
                ));
            }
            if !seen_codes.insert(err.code()) {
                return TestResult::fail(format!("duplicate error code {}", err.code()));
            }
            if !err.to_string().starts_with(expected_code) {
                return TestResult::fail(format!("display output omits code prefix: {err}"));
            }
        }

        TestResult::pass()
    }
}

pub struct ErrorStructureTest;

impl ConformanceTest for ErrorStructureTest {
    fn id(&self) -> &str {
        "R6.2"
    }
    fn name(&self) -> &str {
        "Error structure validation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::ErrorHandling
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "6"
    }
    fn description(&self) -> &str {
        "MUST provide structured error information"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let out_of_range = ProofError::SequenceOutOfRange {
            sequence: 9,
            tree_size: 4,
        };
        let encoded = match serde_json::to_value(&out_of_range) {
            Ok(value) => value,
            Err(err) => return TestResult::fail(format!("error did not serialize: {err}")),
        };
        if encoded.get("SequenceOutOfRange").is_none() {
            return TestResult::fail(format!(
                "structured error is missing variant name: {encoded}"
            ));
        }
        let fields = encoded
            .get("SequenceOutOfRange")
            .and_then(serde_json::Value::as_object)
            .expect("checked variant object");
        if fields.get("sequence") != Some(&serde_json::json!(9))
            || fields.get("tree_size") != Some(&serde_json::json!(4))
        {
            return TestResult::fail(format!("structured fields were not preserved: {encoded}"));
        }

        let invalid = ProofError::InvalidProof {
            reason: "tampered root".to_string(),
        };
        let decoded: ProofError = match serde_json::from_value(
            serde_json::to_value(&invalid).expect("serialize invalid proof"),
        ) {
            Ok(decoded) => decoded,
            Err(err) => return TestResult::fail(format!("error did not deserialize: {err}")),
        };
        if decoded != invalid {
            return TestResult::fail("error round-trip did not preserve variant payload");
        }

        TestResult::pass()
    }
}

pub struct ErrorFailClosedTest;

impl ConformanceTest for ErrorFailClosedTest {
    fn id(&self) -> &str {
        "R6.3"
    }
    fn name(&self) -> &str {
        "Fail-closed error handling"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "6"
    }
    fn description(&self) -> &str {
        "MUST fail closed on errors"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let stream = ctx.generate_markers(3, "fail-closed-errors");
        let disabled = MmrCheckpoint::disabled();
        if let Some(result) =
            expect_error_code(mmr_inclusion_proof(&stream, &disabled, 0), "MMR_DISABLED")
        {
            return result;
        }

        let empty_stream = MarkerStream::new();
        let mut empty_checkpoint = MmrCheckpoint::enabled();
        if let Some(result) = expect_error_code(
            empty_checkpoint.rebuild_from_stream(&empty_stream),
            "MMR_EMPTY_CHECKPOINT",
        ) {
            return result;
        }

        let checkpoint = ctx.create_checkpoint(&stream);
        let proof = match mmr_inclusion_proof(&stream, &checkpoint, 1) {
            Ok(proof) => proof,
            Err(err) => return TestResult::fail(format!("setup proof failed: {err}")),
        };
        let mut tampered_root = checkpoint.root().expect("root").clone();
        tampered_root.root_hash = marker_leaf_hash("tampered-root");
        let marker_hash = stream.get(1).expect("marker").marker_hash.clone();
        if let Some(result) = expect_error_code(
            verify_inclusion(&proof, &tampered_root, &marker_hash),
            "MMR_ROOT_MISMATCH",
        ) {
            return result;
        }

        TestResult::pass()
    }
}
