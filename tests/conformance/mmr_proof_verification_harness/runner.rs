//! Test runner for MMR conformance testing.

use super::context::TestContext;
use super::logging::{EventCode, LogLevel, TestEvent, TestPhase};
use super::traits::{ConformanceTest, RequirementLevel, TestResult, TestStats};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Main conformance test runner
pub struct ConformanceRunner {
    tests: Vec<Box<dyn ConformanceTest + Send + Sync>>,
    context: TestContext,
}

impl ConformanceRunner {
    /// Create a new conformance runner with the given context
    pub fn new(context: TestContext) -> Self {
        Self {
            tests: Vec::new(),
            context,
        }
    }

    /// Register a conformance test
    pub fn register(&mut self, test: Box<dyn ConformanceTest + Send + Sync>) {
        self.tests.push(test);
    }

    /// Register all tests from inventory (if using the inventory crate)
    pub fn register_all_tests(&mut self) {
        // This would integrate with the inventory crate if available
        // For now, tests are registered manually
    }

    /// Run all registered tests
    pub fn run_all(&self) -> ConformanceReport {
        let start_time = Instant::now();

        // Log harness initialization
        self.context.log(&TestEvent::new(
            LogLevel::Info,
            EventCode::HarnessInit,
            format!(
                "Starting conformance test run with {} tests",
                self.tests.len()
            ),
            &self.context.run_id,
        ));

        let mut results = Vec::new();
        let mut stats = TestStats::default();

        for test in &self.tests {
            // Check if test should be filtered
            if let Some(ref filter) = self.context.config.filter
                && !test.id().contains(filter)
                && !test.name().contains(filter)
            {
                continue;
            }

            // Run individual test
            let result = self.run_single_test(test.as_ref());
            self.update_stats(&mut stats, &test.requirement_level(), &result);

            results.push(TestExecution {
                test_id: test.id().to_string(),
                test_name: test.name().to_string(),
                category: test.category(),
                requirement_level: test.requirement_level(),
                spec_section: test.spec_section().to_string(),
                description: test.description().to_string(),
                result,
                duration: Duration::from_millis(0), // Will be filled by run_single_test
            });

            // Fail fast if configured
            if self.context.config.fail_fast && results.last().unwrap().result.is_failing() {
                break;
            }
        }

        let total_duration = start_time.elapsed();

        // Log harness shutdown
        self.context.log(
            &TestEvent::new(
                LogLevel::Info,
                EventCode::HarnessShutdown,
                format!("Completed conformance test run in {:?}", total_duration),
                &self.context.run_id,
            )
            .with_duration(total_duration.as_millis() as u64),
        );

        let is_conformant = stats.is_conformant();
        ConformanceReport {
            run_id: self.context.run_id.clone(),
            stats,
            results,
            total_duration,
            is_conformant,
        }
    }

    /// Run a single test with full setup/teardown
    fn run_single_test(&self, test: &dyn ConformanceTest) -> TestResult {
        let start_time = Instant::now();

        // Log test start
        self.context.log(
            &TestEvent::new(
                LogLevel::Info,
                EventCode::TestStart,
                format!("Starting test: {} - {}", test.id(), test.name()),
                &self.context.run_id,
            )
            .with_test_id(test.id())
            .with_phase(TestPhase::Setup),
        );

        // Create a mutable copy of context for test setup
        let mut test_context = self.context.clone();

        // Run setup
        if let Err(e) = test.setup(&mut test_context) {
            let result = TestResult::error(format!("Setup failed: {}", e));
            self.log_test_result(test, &result, start_time.elapsed());
            return result;
        }

        // Execute the actual test
        self.context.log(
            &TestEvent::new(
                LogLevel::Debug,
                EventCode::TestCase,
                format!("Executing test logic: {}", test.id()),
                &self.context.run_id,
            )
            .with_test_id(test.id())
            .with_phase(TestPhase::Execute),
        );

        let result = test.run(&test_context);

        // Run cleanup
        if let Err(e) = test.cleanup(&mut test_context) {
            self.context.log(
                &TestEvent::new(
                    LogLevel::Warn,
                    EventCode::TestError,
                    format!("Cleanup failed for {}: {}", test.id(), e),
                    &self.context.run_id,
                )
                .with_test_id(test.id())
                .with_phase(TestPhase::Cleanup),
            );
        }

        let duration = start_time.elapsed();
        self.log_test_result(test, &result, duration);
        result
    }

    /// Log test result
    fn log_test_result(&self, test: &dyn ConformanceTest, result: &TestResult, duration: Duration) {
        let (level, event_code) = match result {
            TestResult::Pass => (LogLevel::Info, EventCode::TestPass),
            TestResult::Fail { .. } => (LogLevel::Error, EventCode::TestFail),
            TestResult::Skipped { .. } => (LogLevel::Info, EventCode::TestSkip),
            TestResult::ExpectedFailure { .. } => (LogLevel::Info, EventCode::TestXfail),
            TestResult::Error { .. } => (LogLevel::Error, EventCode::TestError),
        };

        self.context.log(
            &TestEvent::new(
                level,
                event_code,
                format!("Test {}: {}", test.id(), result),
                &self.context.run_id,
            )
            .with_test_id(test.id())
            .with_duration(duration.as_millis() as u64)
            .with_phase(TestPhase::Summary)
            .with_details(serde_json::json!({
                "requirement_level": test.requirement_level(),
                "category": test.category(),
                "spec_section": test.spec_section()
            })),
        );
    }

    /// Update test statistics
    fn update_stats(&self, stats: &mut TestStats, level: &RequirementLevel, result: &TestResult) {
        stats.total += 1;

        match result {
            TestResult::Pass => stats.passed += 1,
            TestResult::Fail { .. } => stats.failed += 1,
            TestResult::Skipped { .. } => stats.skipped += 1,
            TestResult::ExpectedFailure { .. } => stats.expected_failures += 1,
            TestResult::Error { .. } => stats.errors += 1,
        }

        match level {
            RequirementLevel::Must => {
                stats.must_total += 1;
                if result.is_passing() {
                    stats.must_passed += 1;
                }
            }
            RequirementLevel::Should => {
                stats.should_total += 1;
                if result.is_passing() {
                    stats.should_passed += 1;
                }
            }
            RequirementLevel::May => {
                stats.may_total += 1;
                if result.is_passing() {
                    stats.may_passed += 1;
                }
            }
        }
    }
}

/// Complete conformance test report
#[derive(Debug, serde::Serialize)]
pub struct ConformanceReport {
    pub run_id: String,
    pub stats: TestStats,
    pub results: Vec<TestExecution>,
    pub total_duration: Duration,
    pub is_conformant: bool,
}

impl ConformanceReport {
    /// Generate markdown summary report
    pub fn generate_markdown(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!(
            "# MMR Proof Verification Conformance Report\n\n\
             **Run ID:** `{}`  \n\
             **Duration:** {:?}  \n\
             **Conformant:** {}  \n\n",
            self.run_id,
            self.total_duration,
            if self.is_conformant {
                "✅ YES"
            } else {
                "❌ NO"
            }
        ));

        // Overall statistics
        report.push_str("## Overall Statistics\n\n");
        report.push_str(&format!(
            "| Metric | Count | Percentage |\n\
             |--------|-------|------------|\n\
             | Total Tests | {} | 100.0% |\n\
             | Passed | {} | {:.1}% |\n\
             | Failed | {} | {:.1}% |\n\
             | Skipped | {} | {:.1}% |\n\
             | Expected Failures | {} | {:.1}% |\n\
             | Errors | {} | {:.1}% |\n\n",
            self.stats.total,
            self.stats.passed,
            self.stats.passed as f64 / self.stats.total as f64 * 100.0,
            self.stats.failed,
            self.stats.failed as f64 / self.stats.total as f64 * 100.0,
            self.stats.skipped,
            self.stats.skipped as f64 / self.stats.total as f64 * 100.0,
            self.stats.expected_failures,
            self.stats.expected_failures as f64 / self.stats.total as f64 * 100.0,
            self.stats.errors,
            self.stats.errors as f64 / self.stats.total as f64 * 100.0,
        ));

        // Requirement level breakdown
        report.push_str("## Requirement Level Coverage\n\n");
        report.push_str(&format!(
            "| Level | Passed | Total | Coverage |\n\
             |-------|--------|-------|---------|\n\
             | MUST | {} | {} | {:.1}% |\n\
             | SHOULD | {} | {} | {:.1}% |\n\
             | MAY | {} | {} | {:.1}% |\n\n",
            self.stats.must_passed,
            self.stats.must_total,
            self.stats.must_pass_rate() * 100.0,
            self.stats.should_passed,
            self.stats.should_total,
            if self.stats.should_total > 0 {
                self.stats.should_passed as f64 / self.stats.should_total as f64 * 100.0
            } else {
                100.0
            },
            self.stats.may_passed,
            self.stats.may_total,
            if self.stats.may_total > 0 {
                self.stats.may_passed as f64 / self.stats.may_total as f64 * 100.0
            } else {
                100.0
            }
        ));

        // Detailed results by category
        let mut by_category: HashMap<String, Vec<&TestExecution>> = HashMap::new();
        for result in &self.results {
            by_category
                .entry(result.category.to_string())
                .or_default()
                .push(result);
        }

        for (category, tests) in by_category {
            report.push_str(&format!("### {} Tests\n\n", category));
            report.push_str("| ID | Name | Level | Result |\n|---|------|-------|--------|\n");

            for test in tests {
                let status_icon = match &test.result {
                    TestResult::Pass => "✅",
                    TestResult::ExpectedFailure { .. } => "⚠️",
                    TestResult::Fail { .. } => "❌",
                    TestResult::Error { .. } => "💥",
                    TestResult::Skipped { .. } => "⏭️",
                };
                let status_text = match &test.result {
                    TestResult::Pass => "PASS".to_string(),
                    TestResult::ExpectedFailure { discrepancy_id, .. } => {
                        format!("XFAIL ({discrepancy_id})")
                    }
                    TestResult::Fail { reason, .. }
                    | TestResult::Error { reason }
                    | TestResult::Skipped { reason } => reason.clone(),
                };

                report.push_str(&format!(
                    "| {} | {} | {} | {} {} |\n",
                    test.test_id, test.test_name, test.requirement_level, status_icon, status_text
                ));
            }
            report.push('\n');
        }

        report
    }

    /// Save report to JSON file
    pub fn save_json(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Save markdown report to file
    pub fn save_markdown(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let markdown = self.generate_markdown();
        std::fs::write(path, markdown)?;
        Ok(())
    }
}

/// Individual test execution record
#[derive(Debug, serde::Serialize)]
pub struct TestExecution {
    pub test_id: String,
    pub test_name: String,
    pub category: super::traits::TestCategory,
    pub requirement_level: RequirementLevel,
    pub spec_section: String,
    pub description: String,
    pub result: TestResult,
    pub duration: Duration,
}
