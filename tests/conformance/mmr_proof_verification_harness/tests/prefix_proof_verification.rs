//! Prefix proof verification conformance tests (R5.*).
use super::super::*;

fn checkpoint_pair(
    ctx: &TestContext,
    prefix_count: u64,
    super_count: u64,
) -> (MmrCheckpoint, MmrCheckpoint) {
    let prefix_stream = ctx.generate_markers(prefix_count, "verify-prefix");
    let super_stream = ctx.generate_markers(super_count, "verify-prefix");
    (
        ctx.create_checkpoint(&prefix_stream),
        ctx.create_checkpoint(&super_stream),
    )
}

fn flip_first_char(value: &str) -> String {
    let mut bytes = value.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).expect("hash string remains utf-8")
}

pub struct PrefixVerificationValidTest;

impl ConformanceTest for PrefixVerificationValidTest {
    fn id(&self) -> &str {
        "R5.1"
    }
    fn name(&self) -> &str {
        "Valid prefix verification"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "5"
    }
    fn description(&self) -> &str {
        "MUST verify valid prefix proofs"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (prefix_checkpoint, super_checkpoint) = checkpoint_pair(ctx, 3, 9);
        let proof = match mmr_prefix_proof(&prefix_checkpoint, &super_checkpoint) {
            Ok(proof) => proof,
            Err(err) => return TestResult::fail(format!("prefix generation failed: {err}")),
        };

        match verify_prefix(
            &proof,
            prefix_checkpoint.root().expect("prefix root"),
            super_checkpoint.root().expect("super root"),
        ) {
            Ok(()) => TestResult::pass(),
            Err(err) => TestResult::fail(format!("valid prefix proof was rejected: {err}")),
        }
    }
}

pub struct PrefixVerificationInvalidSizesTest;

impl ConformanceTest for PrefixVerificationInvalidSizesTest {
    fn id(&self) -> &str {
        "R5.2"
    }
    fn name(&self) -> &str {
        "Invalid size rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "5"
    }
    fn description(&self) -> &str {
        "MUST reject invalid size relationships"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (prefix_checkpoint, super_checkpoint) = checkpoint_pair(ctx, 3, 9);
        let mut proof = match mmr_prefix_proof(&prefix_checkpoint, &super_checkpoint) {
            Ok(proof) => proof,
            Err(err) => return TestResult::fail(format!("prefix generation failed: {err}")),
        };
        proof.prefix_size = 10;

        match verify_prefix(
            &proof,
            prefix_checkpoint.root().expect("prefix root"),
            super_checkpoint.root().expect("super root"),
        ) {
            Err(err) if err.code() == "MMR_PREFIX_SIZE_INVALID" => TestResult::pass(),
            Err(err) => TestResult::fail(format!("unexpected error: {err}")),
            Ok(()) => TestResult::fail("invalid size relationship was accepted"),
        }
    }
}

pub struct PrefixVerificationMismatchedRootSizesTest;

impl ConformanceTest for PrefixVerificationMismatchedRootSizesTest {
    fn id(&self) -> &str {
        "R5.3"
    }
    fn name(&self) -> &str {
        "Root size mismatch rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "5"
    }
    fn description(&self) -> &str {
        "MUST reject mismatched root sizes"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (prefix_checkpoint, super_checkpoint) = checkpoint_pair(ctx, 4, 8);
        let proof = match mmr_prefix_proof(&prefix_checkpoint, &super_checkpoint) {
            Ok(proof) => proof,
            Err(err) => return TestResult::fail(format!("prefix generation failed: {err}")),
        };
        let mut wrong_root = prefix_checkpoint.root().expect("prefix root").clone();
        wrong_root.tree_size = wrong_root.tree_size.saturating_add(1);

        match verify_prefix(
            &proof,
            &wrong_root,
            super_checkpoint.root().expect("super root"),
        ) {
            Err(err) if err.code() == "MMR_INVALID_PROOF" => TestResult::pass(),
            Err(err) => TestResult::fail(format!("unexpected error: {err}")),
            Ok(()) => TestResult::fail("root size mismatch was accepted"),
        }
    }
}

pub struct PrefixVerificationRootRelationshipsTest;

impl ConformanceTest for PrefixVerificationRootRelationshipsTest {
    fn id(&self) -> &str {
        "R5.4"
    }
    fn name(&self) -> &str {
        "Root relationship validation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "5"
    }
    fn description(&self) -> &str {
        "MUST validate all root relationships"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (prefix_checkpoint, super_checkpoint) = checkpoint_pair(ctx, 5, 10);
        let mut proof = match mmr_prefix_proof(&prefix_checkpoint, &super_checkpoint) {
            Ok(proof) => proof,
            Err(err) => return TestResult::fail(format!("prefix generation failed: {err}")),
        };
        proof.super_leaf_hashes[0] = marker_leaf_hash("relationship-tamper");

        match verify_prefix(
            &proof,
            prefix_checkpoint.root().expect("prefix root"),
            super_checkpoint.root().expect("super root"),
        ) {
            Err(err) if err.code() == "MMR_ROOT_MISMATCH" => TestResult::pass(),
            Err(err) => TestResult::fail(format!("unexpected error: {err}")),
            Ok(()) => TestResult::fail("tampered super leaves were accepted"),
        }
    }
}

pub struct PrefixVerificationConstantTimeTest;

impl ConformanceTest for PrefixVerificationConstantTimeTest {
    fn id(&self) -> &str {
        "R5.5"
    }
    fn name(&self) -> &str {
        "Constant-time root validation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "5"
    }
    fn description(&self) -> &str {
        "MUST use constant-time comparisons"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (prefix_checkpoint, super_checkpoint) = checkpoint_pair(ctx, 6, 12);
        let mut proof = match mmr_prefix_proof(&prefix_checkpoint, &super_checkpoint) {
            Ok(proof) => proof,
            Err(err) => return TestResult::fail(format!("prefix generation failed: {err}")),
        };
        proof.prefix_root_hash = flip_first_char(&proof.prefix_root_hash);

        match verify_prefix(
            &proof,
            prefix_checkpoint.root().expect("prefix root"),
            super_checkpoint.root().expect("super root"),
        ) {
            Err(err) if err.code() == "MMR_ROOT_MISMATCH" => TestResult::pass(),
            Err(err) => TestResult::fail(format!("unexpected error: {err}")),
            Ok(()) => TestResult::fail("same-length tampered root was accepted"),
        }
    }
}
