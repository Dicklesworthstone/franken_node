//! bd-tg2 Fleet Quarantine/Revocation API Conformance Test Runner
//!
//! This binary executes the complete bd-tg2 conformance test suite and generates
//! detailed compliance reports in both JSON and Markdown formats.

#[cfg(any())]
mod legacy_runner {
    use serde_json;
    use std::process;

    // Import the conformance test module
    mod bd_tg2_fleet_quarantine_conformance {
        include!("../../../tests/conformance/bd_tg2_fleet_quarantine_conformance.rs");
    }
}

fn main() {
    eprintln!(
        "bd-tg2 conformance is exercised through the registered cargo test target, not this bin."
    );
    std::process::exit(2);
}

#[cfg(any())]
fn main() {
    println!("🚀 bd-tg2 Fleet Quarantine/Revocation API Conformance Test Suite");
    println!("================================================================\n");

    // Run the conformance test suite
    let report = bd_tg2_fleet_quarantine_conformance::run_bd_tg2_conformance_tests();

    // Print summary to console
    println!("📊 Test Results Summary:");
    println!("  Total tests: {}", report.results.len());
    println!("  MUST requirements:");
    println!("    ✅ Pass: {}", report.stats.must_pass);
    println!("    ❌ Fail: {}", report.stats.must_fail);
    println!("  SHOULD requirements:");
    println!("    ✅ Pass: {}", report.stats.should_pass);
    println!("    ❌ Fail: {}", report.stats.should_fail);
    println!("  MAY requirements:");
    println!("    ✅ Pass: {}", report.stats.may_pass);
    println!("    ❌ Fail: {}", report.stats.may_fail);
    println!("  Other:");
    println!("    ⏳ XFAIL: {}", report.stats.expected_failures);
    println!("    ⏭️  Skip: {}", report.stats.skipped);

    let compliance_score = report.compliance_score();
    println!("\n🎯 Compliance Score: {:.1}%", compliance_score * 100.0);

    if compliance_score >= 0.95 {
        println!("✅ CONFORMANT - Meets bd-tg2 specification requirements");
    } else {
        println!("❌ NON-CONFORMANT - Does not meet bd-tg2 specification requirements");

        // List failed MUST requirements
        println!("\n🔍 Failed MUST Requirements:");
        for record in report.results.values() {
            if let (
                bd_tg2_fleet_quarantine_conformance::RequirementLevel::Must,
                bd_tg2_fleet_quarantine_conformance::TestResult::Fail { reason },
            ) = (record.level, &record.result)
            {
                println!("  - {}: {}", record.id, reason);
            }
        }
    }

    // Write detailed reports
    println!("\n📄 Generating Reports:");

    // JSON report for machine consumption
    let json_report =
        serde_json::to_string_pretty(&report).expect("Failed to serialize conformance report");

    std::fs::write("bd_tg2_conformance_report.json", json_report)
        .expect("Failed to write JSON report");
    println!("  📄 JSON: bd_tg2_conformance_report.json");

    // Markdown report for human consumption
    let markdown_report = report.to_markdown();
    std::fs::write("bd_tg2_conformance_report.md", markdown_report)
        .expect("Failed to write Markdown report");
    println!("  📄 Markdown: bd_tg2_conformance_report.md");

    // Exit code based on conformance
    if report.stats.must_fail > 0 {
        println!("\n❌ Exiting with code 1 due to MUST requirement failures");
        process::exit(1);
    } else {
        println!("\n✅ All MUST requirements passed");
        process::exit(0);
    }
}
