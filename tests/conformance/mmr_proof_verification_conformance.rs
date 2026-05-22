//! Main conformance test runner for MMR proof verification system.
//!
//! This integrates all MMR conformance tests and generates comprehensive reports
//! following the testing-conformance-harnesses pattern.

mod mmr_proof_verification_harness;

use mmr_proof_verification_harness::*;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize test context
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("conformance")
        .join("mmr_artifacts");

    let context = TestContext::new(base_dir)?;

    // Create runner and register all tests
    let mut runner = ConformanceRunner::new(context);
    mmr_proof_verification_harness::tests::register_all_tests(&mut runner);

    println!("🔍 MMR Proof Verification Conformance Testing");
    println!("===============================================");
    println!();

    // Run all conformance tests
    let report = runner.run_all();

    // Print summary
    println!("📊 Test Results Summary");
    println!("----------------------");
    println!("Total tests: {}", report.stats.total);
    println!("Passed: {}", report.stats.passed);
    println!("Failed: {}", report.stats.failed);
    println!("Skipped: {}", report.stats.skipped);
    println!("Expected failures: {}", report.stats.expected_failures);
    println!("Errors: {}", report.stats.errors);
    println!();

    // Requirement level breakdown
    println!("📋 Requirement Level Coverage");
    println!("------------------------------");
    println!("MUST:   {}/{} ({:.1}%)",
        report.stats.must_passed,
        report.stats.must_total,
        report.stats.must_pass_rate() * 100.0);
    println!("SHOULD: {}/{} ({:.1}%)",
        report.stats.should_passed,
        report.stats.should_total,
        if report.stats.should_total > 0 {
            report.stats.should_passed as f64 / report.stats.should_total as f64 * 100.0
        } else { 100.0 });
    println!("MAY:    {}/{} ({:.1}%)",
        report.stats.may_passed,
        report.stats.may_total,
        if report.stats.may_total > 0 {
            report.stats.may_passed as f64 / report.stats.may_total as f64 * 100.0
        } else { 100.0 });
    println!();

    // Conformance verdict
    if report.is_conformant {
        println!("✅ CONFORMANCE: PASS");
        println!("   The implementation meets MMR specification requirements.");
    } else {
        println!("❌ CONFORMANCE: FAIL");
        println!("   MUST requirement coverage is below 95% threshold.");
    }
    println!();

    // Save detailed reports
    let output_dir = PathBuf::from("tests/conformance/mmr_artifacts/output");
    std::fs::create_dir_all(&output_dir)?;

    let json_path = output_dir.join(format!("conformance_report_{}.json", report.run_id));
    let md_path = output_dir.join(format!("conformance_report_{}.md", report.run_id));

    report.save_json(&json_path)?;
    report.save_markdown(&md_path)?;

    println!("📄 Reports generated:");
    println!("   JSON: {}", json_path.display());
    println!("   Markdown: {}", md_path.display());

    // Exit with appropriate code
    if report.is_conformant && report.stats.failed == 0 && report.stats.errors == 0 {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn conformance_harness_integration() {
        // Basic integration test to verify harness works
        let base_dir = std::env::temp_dir().join("mmr_conformance_test");
        let context = TestContext::new(base_dir).expect("context");
        let mut runner = ConformanceRunner::new(context);

        // Register a few key tests
        runner.register(Box::new(
            mmr_proof_verification_harness::tests::checkpoint_management::CheckpointEnabledDisabledTest
        ));
        runner.register(Box::new(
            mmr_proof_verification_harness::tests::inclusion_proof_generation::InclusionProofValidGenerationTest
        ));

        let report = runner.run_all();
        assert!(report.stats.total >= 2);
        assert!(report.stats.must_total >= 2);
    }

    #[test]
    fn test_context_marker_generation() {
        let base_dir = std::env::temp_dir().join("mmr_context_test");
        let context = TestContext::new(base_dir).expect("context");

        let stream = context.generate_markers(10, "test");
        assert_eq!(stream.len(), 10);

        // Verify deterministic generation
        let stream2 = context.generate_markers(10, "test");
        assert_eq!(stream.len(), stream2.len());

        // Should be different with different seeds/prefixes
        let stream3 = context.generate_markers(10, "different");
        assert_eq!(stream3.len(), 10);
    }

    #[test]
    fn test_checkpoint_creation() {
        let base_dir = std::env::temp_dir().join("mmr_checkpoint_test");
        let context = TestContext::new(base_dir).expect("context");

        let stream = context.generate_markers(5, "checkpoint");
        let cp = context.create_checkpoint(&stream);

        assert!(cp.is_enabled());
        assert_eq!(cp.tree_size(), 5);
        assert!(cp.root().is_some());
    }
}