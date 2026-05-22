//! Serialization conformance tests (R8.*) - Placeholder implementation.
use super::super::*;

macro_rules! placeholder_test {
    ($struct_name:ident, $id:expr, $name:expr, $category:expr, $level:expr, $section:expr, $desc:expr) => {
        pub struct $struct_name;
        impl ConformanceTest for $struct_name {
            fn id(&self) -> &str { $id }
            fn name(&self) -> &str { $name }
            fn category(&self) -> TestCategory { $category }
            fn requirement_level(&self) -> RequirementLevel { $level }
            fn spec_section(&self) -> &str { $section }
            fn description(&self) -> &str { $desc }
            fn run(&self, _ctx: &TestContext) -> TestResult { TestResult::skipped("Implementation pending") }
        }
    };
}

placeholder_test!(JsonRoundTripTest, "R8.1", "JSON round-trip serialization", TestCategory::Serialization, RequirementLevel::Should, "8", "SHOULD support JSON serialization");
placeholder_test!(ProofFieldPreservationTest, "R8.2", "Proof field preservation", TestCategory::Serialization, RequirementLevel::Should, "8", "SHOULD preserve all proof fields");
placeholder_test!(MalformedRejectionTest, "R8.3", "Malformed input rejection", TestCategory::Serialization, RequirementLevel::Should, "8", "SHOULD reject malformed inputs");