//! Performance conformance tests - Placeholder implementation.
use super::super::*;

macro_rules! placeholder_test {
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

placeholder_test!(
    AuditPathScalingTest,
    "P1",
    "Audit path scaling validation",
    TestCategory::Performance,
    RequirementLevel::Should,
    "Performance",
    "Audit path should scale logarithmically"
);
placeholder_test!(
    LargeTreePerformanceTest,
    "P2",
    "Large tree performance",
    TestCategory::Performance,
    RequirementLevel::Should,
    "Performance",
    "Should handle large trees efficiently"
);
