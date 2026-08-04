//! Inclusion Proof Verification conformance tests (R3.*).

use super::super::*;

fn inclusion_fixture(
    ctx: &TestContext,
    seq: u64,
) -> Result<(InclusionProof, MmrRoot, String), TestResult> {
    let stream = ctx.generate_markers(10, "verify-inclusion");
    let checkpoint = ctx.create_checkpoint(&stream);
    let root = checkpoint.root().expect("checkpoint root").clone();
    let marker_hash = stream
        .get(seq)
        .map(|marker| marker.marker_hash.clone())
        .ok_or_else(|| TestResult::fail(format!("missing marker for sequence {seq}")))?;
    let proof = mmr_inclusion_proof(&stream, &checkpoint, seq)
        .map_err(|err| TestResult::fail(format!("proof generation failed: {err}")))?;
    Ok((proof, root, marker_hash))
}

fn tamper_first_char(value: &str) -> String {
    let mut tampered = value.to_string();
    let replacement = if tampered.as_bytes().first() == Some(&b'f') {
        "0"
    } else {
        "f"
    };
    tampered.replace_range(0..1, replacement);
    tampered
}

pub struct InclusionVerificationValidTest;

impl ConformanceTest for InclusionVerificationValidTest {
    fn id(&self) -> &str {
        "R3.1"
    }
    fn name(&self) -> &str {
        "Valid inclusion proof verification"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "3"
    }
    fn description(&self) -> &str {
        "MUST verify valid inclusion proofs successfully"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        for seq in [0, 4, 9] {
            let (proof, root, marker_hash) = match inclusion_fixture(ctx, seq) {
                Ok(fixture) => fixture,
                Err(result) => return result,
            };

            if let Err(err) = verify_inclusion(&proof, &root, &marker_hash) {
                return TestResult::fail(format!(
                    "valid proof for sequence {seq} failed verification: {err}"
                ));
            }
        }

        TestResult::pass()
    }
}

pub struct InclusionVerificationWrongMarkerTest;

impl ConformanceTest for InclusionVerificationWrongMarkerTest {
    fn id(&self) -> &str {
        "R3.2"
    }
    fn name(&self) -> &str {
        "Wrong marker hash rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "3"
    }
    fn description(&self) -> &str {
        "MUST reject proofs with wrong marker hash"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (proof, root, _) = match inclusion_fixture(ctx, 5) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };

        match verify_inclusion(&proof, &root, &"wrong-marker".to_string()) {
            Err(err) => comparison::assert_error_code("MMR_LEAF_MISMATCH", &err),
            Ok(()) => TestResult::fail("wrong marker hash was accepted"),
        }
    }
}

pub struct InclusionVerificationWrongRootTest;

impl ConformanceTest for InclusionVerificationWrongRootTest {
    fn id(&self) -> &str {
        "R3.3"
    }
    fn name(&self) -> &str {
        "Wrong root hash rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "3"
    }
    fn description(&self) -> &str {
        "MUST reject proofs with wrong root hash"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (proof, mut root, marker_hash) = match inclusion_fixture(ctx, 5) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        root.root_hash = marker_leaf_hash("wrong-root");

        match verify_inclusion(&proof, &root, &marker_hash) {
            Err(err) => comparison::assert_error_code("MMR_ROOT_MISMATCH", &err),
            Ok(()) => TestResult::fail("wrong root hash was accepted"),
        }
    }
}

pub struct InclusionVerificationTreeSizeMismatchTest;

impl ConformanceTest for InclusionVerificationTreeSizeMismatchTest {
    fn id(&self) -> &str {
        "R3.4"
    }
    fn name(&self) -> &str {
        "Tree size mismatch rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "3"
    }
    fn description(&self) -> &str {
        "MUST reject proofs with tree size mismatch"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (proof, mut root, marker_hash) = match inclusion_fixture(ctx, 5) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        root.tree_size += 1;

        match verify_inclusion(&proof, &root, &marker_hash) {
            Err(err) => comparison::assert_error_code("MMR_INVALID_PROOF", &err),
            Ok(()) => TestResult::fail("tree-size mismatch was accepted"),
        }
    }
}

pub struct InclusionVerificationLeafIndexBoundaryTest;

impl ConformanceTest for InclusionVerificationLeafIndexBoundaryTest {
    fn id(&self) -> &str {
        "R3.5"
    }
    fn name(&self) -> &str {
        "Leaf index boundary validation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "3"
    }
    fn description(&self) -> &str {
        "MUST reject proofs with leaf_index >= tree_size"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (mut proof, root, marker_hash) = match inclusion_fixture(ctx, 5) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        proof.leaf_index = proof.tree_size;

        match verify_inclusion(&proof, &root, &marker_hash) {
            Err(err) => comparison::assert_error_code("MMR_SEQUENCE_OUT_OF_RANGE", &err),
            Ok(()) => TestResult::fail("leaf_index >= tree_size was accepted"),
        }
    }
}

pub struct InclusionVerificationOversizedAuditPathTest;

impl ConformanceTest for InclusionVerificationOversizedAuditPathTest {
    fn id(&self) -> &str {
        "R3.6"
    }
    fn name(&self) -> &str {
        "Oversized audit path rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "3"
    }
    fn description(&self) -> &str {
        "MUST reject proofs with oversized audit paths"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (mut proof, root, marker_hash) = match inclusion_fixture(ctx, 5) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        proof.audit_path = vec![marker_leaf_hash("oversized-path-entry"); 65];

        match verify_inclusion(&proof, &root, &marker_hash) {
            Err(err) => comparison::assert_error_code("MMR_INVALID_PROOF", &err),
            Ok(()) => TestResult::fail("oversized audit path was accepted"),
        }
    }
}

pub struct InclusionVerificationConstantTimeTest;

impl ConformanceTest for InclusionVerificationConstantTimeTest {
    fn id(&self) -> &str {
        "R3.7"
    }
    fn name(&self) -> &str {
        "Constant-time hash comparisons"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "3"
    }
    fn description(&self) -> &str {
        "MUST use constant-time hash comparisons"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (proof, root, marker_hash) = match inclusion_fixture(ctx, 5) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };

        for tampered_hash in [
            format!("x{marker_hash}"),
            format!("{marker_hash}x"),
            tamper_first_char(&marker_hash),
        ] {
            match verify_inclusion(&proof, &root, &tampered_hash) {
                Err(err) if err.code() == "MMR_LEAF_MISMATCH" => {}
                Err(err) => return TestResult::fail(format!("unexpected error: {err}")),
                Ok(()) => return TestResult::fail("tampered marker hash was accepted"),
            }
        }

        let mut tampered_root = root.clone();
        for position in [0, 31, 63] {
            tampered_root.root_hash = root.root_hash.clone();
            let replacement = if tampered_root.root_hash.as_bytes()[position] == b'f' {
                "0"
            } else {
                "f"
            };
            tampered_root
                .root_hash
                .replace_range(position..position + 1, replacement);

            match verify_inclusion(&proof, &tampered_root, &marker_hash) {
                Err(err) if err.code() == "MMR_ROOT_MISMATCH" => {}
                Err(err) => return TestResult::fail(format!("unexpected error: {err}")),
                Ok(()) => return TestResult::fail("tampered root hash was accepted"),
            }
        }

        TestResult::pass()
    }
}
