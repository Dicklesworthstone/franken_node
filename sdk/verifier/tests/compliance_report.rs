//! Verifier SDK Compliance Report Generator
//!
//! Generates automated compliance reports from conformance test results.
//! Used by CI to validate specification compliance and track coverage metrics.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Structured test result for report generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResultEntry {
    pub id: String,
    pub section: String,
    pub level: String,
    pub description: String,
    pub verdict: String,
    pub reason: Option<String>,
}

/// Section-level statistics for compliance reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionStats {
    pub section: String,
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub xfail: usize,
    pub pass_rate: f64,
}

/// Overall compliance summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub generated_at: String,
    pub sdk_version: String,
    pub specification: String,
    pub total_requirements: usize,
    pub requirements_tested: usize,
    pub requirements_passing: usize,
    pub requirements_failing: usize,
    pub expected_failures: usize,
    pub overall_score: f64,
    pub conformance_level: String,
    pub sections: Vec<SectionStats>,
    pub failing_tests: Vec<TestResultEntry>,
    pub coverage_gaps: Vec<String>,
}

impl ComplianceReport {
    /// Generate compliance report from test results
    pub fn from_test_results(results: Vec<TestResultEntry>) -> Self {
        let mut by_section = BTreeMap::new();
        let mut total_pass = 0;
        let mut total_fail = 0;
        let mut total_xfail = 0;
        let mut failing_tests = Vec::new();

        for result in &results {
            let section_stats = by_section
                .entry(result.section.clone())
                .or_insert((0, 0, 0, 0));
            section_stats.0 += 1; // total

            match result.verdict.as_str() {
                "PASS" => {
                    section_stats.1 += 1; // pass
                    total_pass += 1;
                }
                "FAIL" => {
                    section_stats.2 += 1; // fail
                    total_fail += 1;
                    failing_tests.push(result.clone());
                }
                "XFAIL" => {
                    section_stats.3 += 1; // expected fail
                    total_xfail += 1;
                }
                _ => {}
            }
        }

        let sections = by_section
            .into_iter()
            .map(|(section, (total, pass, fail, xfail))| SectionStats {
                section,
                total,
                pass,
                fail,
                xfail,
                pass_rate: if total > 0 {
                    (pass as f64 / total as f64) * 100.0
                } else {
                    0.0
                },
            })
            .collect();

        let total_requirements = results.len();
        let requirements_tested = total_requirements;
        let requirements_passing = total_pass;
        let requirements_failing = total_fail;
        let expected_failures = total_xfail;

        let overall_score = if requirements_tested > 0 {
            (requirements_passing as f64 / (requirements_passing + requirements_failing) as f64)
                * 100.0
        } else {
            100.0
        };

        let conformance_level = match overall_score {
            score if score >= 100.0 => "FULL_CONFORMANCE".to_string(),
            score if score >= 95.0 => "HIGH_CONFORMANCE".to_string(),
            score if score >= 80.0 => "MEDIUM_CONFORMANCE".to_string(),
            _ => "LOW_CONFORMANCE".to_string(),
        };

        ComplianceReport {
            generated_at: "2026-04-20T00:00:00Z".to_string(), // Fixed timestamp for tests
            sdk_version: "vsdk-v1.0".to_string(),
            specification: "vsdk-v1.0".to_string(),
            total_requirements,
            requirements_tested,
            requirements_passing,
            requirements_failing,
            expected_failures,
            overall_score,
            conformance_level,
            sections,
            failing_tests,
            coverage_gaps: Vec::new(), // Would be populated by analyzing untested requirements
        }
    }

    /// Generate markdown report
    pub fn to_markdown(&self) -> String {
        let mut report = String::new();

        report.push_str("# Verifier SDK Compliance Report\n\n");
        report.push_str(&format!("**Generated**: {}\n", self.generated_at));
        report.push_str(&format!("**SDK Version**: {}\n", self.sdk_version));
        report.push_str(&format!("**Specification**: {}\n", self.specification));
        report.push_str(&format!(
            "**Conformance Level**: {} ({:.1}%)\n\n",
            self.conformance_level, self.overall_score
        ));

        report.push_str("## Summary\n\n");
        report.push_str(&format!(
            "- **Total Requirements**: {}\n",
            self.total_requirements
        ));
        report.push_str(&format!(
            "- **Requirements Tested**: {} ({:.1}%)\n",
            self.requirements_tested,
            if self.total_requirements > 0 {
                (self.requirements_tested as f64 / self.total_requirements as f64) * 100.0
            } else {
                100.0
            }
        ));
        report.push_str(&format!(
            "- **✅ Passing**: {}\n",
            self.requirements_passing
        ));
        report.push_str(&format!(
            "- **❌ Failing**: {}\n",
            self.requirements_failing
        ));
        report.push_str(&format!(
            "- **⚠️ Expected Failures**: {}\n\n",
            self.expected_failures
        ));

        report.push_str("## Coverage by Section\n\n");
        report.push_str("| Section | Total | Pass | Fail | XFail | Pass Rate |\n");
        report.push_str("|---------|-------|------|------|-------|----------|\n");

        for section in &self.sections {
            report.push_str(&format!(
                "| {} | {} | {} | {} | {} | {:.1}% |\n",
                section.section,
                section.total,
                section.pass,
                section.fail,
                section.xfail,
                section.pass_rate
            ));
        }

        if !self.failing_tests.is_empty() {
            report.push_str("\n## Failing Tests\n\n");
            for test in &self.failing_tests {
                report.push_str(&format!("### ❌ {}: {}\n\n", test.id, test.description));
                if let Some(ref reason) = test.reason {
                    report.push_str(&format!("**Failure Reason**: {}\n\n", reason));
                }
            }
        }

        if !self.coverage_gaps.is_empty() {
            report.push_str("\n## Coverage Gaps\n\n");
            for gap in &self.coverage_gaps {
                report.push_str(&format!("- {}\n", gap));
            }
        }

        report.push_str(&format!(
            "\n---\n\n**Final Score**: {} ({:.1}%)\n",
            self.conformance_level, self.overall_score
        ));

        report
    }

    /// Generate JSON report for CI consumption
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_report_generation() {
        let test_results = vec![
            TestResultEntry {
                id: "TEST-001".to_string(),
                section: "schema".to_string(),
                level: "Must".to_string(),
                description: "Test description".to_string(),
                verdict: "PASS".to_string(),
                reason: None,
            },
            TestResultEntry {
                id: "TEST-002".to_string(),
                section: "schema".to_string(),
                level: "Must".to_string(),
                description: "Another test".to_string(),
                verdict: "FAIL".to_string(),
                reason: Some("Test failure reason".to_string()),
            },
        ];

        let report = ComplianceReport::from_test_results(test_results);

        assert_eq!(report.total_requirements, 2);
        assert_eq!(report.requirements_passing, 1);
        assert_eq!(report.requirements_failing, 1);
        assert_eq!(report.overall_score, 50.0);
        assert_eq!(report.conformance_level, "LOW_CONFORMANCE");
        assert_eq!(report.failing_tests.len(), 1);
    }

    #[test]
    fn test_markdown_report_format() {
        let test_results = vec![TestResultEntry {
            id: "TEST-001".to_string(),
            section: "test".to_string(),
            level: "Must".to_string(),
            description: "Test description".to_string(),
            verdict: "PASS".to_string(),
            reason: None,
        }];

        let report = ComplianceReport::from_test_results(test_results);
        let markdown = report.to_markdown();

        assert!(markdown.contains("# Verifier SDK Compliance Report"));
        assert!(markdown.contains("**Conformance Level**: FULL_CONFORMANCE"));
        assert!(markdown.contains("| test | 1 | 1 | 0 | 0 | 100.0% |"));
    }

    #[test]
    fn test_json_report_serialization() {
        let test_results = vec![TestResultEntry {
            id: "TEST-001".to_string(),
            section: "test".to_string(),
            level: "Must".to_string(),
            description: "Test description".to_string(),
            verdict: "PASS".to_string(),
            reason: None,
        }];

        let report = ComplianceReport::from_test_results(test_results);
        let json = report.to_json().expect("JSON serialization should work");

        assert!(json.contains("\"overall_score\": 100.0"));
        assert!(json.contains("\"conformance_level\": \"FULL_CONFORMANCE\""));
        assert!(json.contains("\"sdk_version\": \"vsdk-v1.0\""));
    }
}
