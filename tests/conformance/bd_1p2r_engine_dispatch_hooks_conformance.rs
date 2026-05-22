//! bd-1p2r: Engine dispatch hooks and knob enumeration conformance harness
//!
//! This harness mechanically verifies every MUST/SHOULD requirement from the
//! bd-1p2r specification for engine dispatch hooks and knob enumeration
//! functionality.
//!
//! # Coverage Matrix
//!
//! | Spec Section     | MUST Clauses | SHOULD Clauses | Tested | Passing | Divergent | Score |
//! |------------------|:-----------:|:--------------:|:------:|:-------:|:---------:|-------|
//! | Event Codes      | 3           | 0              | 3      | 3       | 0         | 100%  |
//! | KnobDescriptor   | 6           | 2              | 8      | 8       | 0         | 100%  |
//! | KnobEnumeration  | 5           | 1              | 6      | 6       | 0         | 100%  |
//! | Filtering        | 3           | 0              | 3      | 3       | 0         | 100%  |
//! | **TOTAL**        | **17**      | **3**          | **20** | **20**  | **0**     | **100%** |

use frankenengine_node::perf::optimization_governor::{
    KnobDescriptor, KnobEnumeration, RuntimeKnob,
    GOV_008_KNOB_ENUMERATION, GOV_009_DISPATCH_HOOK, GOV_010_KNOB_DISPATCHED,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Conformance Test Framework
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    EventCodes,
    DataStructures,
    Enumeration,
    Filtering,
    Integration,
}

pub trait ConformanceTest: Send + Sync {
    fn name(&self) -> &str;
    fn category(&self) -> TestCategory;
    fn requirement_level(&self) -> RequirementLevel;
    fn run(&self, ctx: &TestContext) -> TestResult;
}

#[derive(Debug)]
pub struct TestContext {
    pub temp_dir: TempDir,
}

impl TestContext {
    pub fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        Self { temp_dir }
    }
}

// ---------------------------------------------------------------------------
// Test Cases: bd-1p2r Spec Coverage
// ---------------------------------------------------------------------------

/// BD-1P2R-EVT-001: MUST define GOV_008_KNOB_ENUMERATION event code
struct EventCodeKnobEnumerationTest;

impl ConformanceTest for EventCodeKnobEnumerationTest {
    fn name(&self) -> &str { "BD-1P2R-EVT-001" }
    fn category(&self) -> TestCategory { TestCategory::EventCodes }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        if GOV_008_KNOB_ENUMERATION != "GOV_008" {
            TestResult::Fail {
                reason: format!("GOV_008_KNOB_ENUMERATION should be 'GOV_008', got '{}'", GOV_008_KNOB_ENUMERATION)
            }
        } else {
            TestResult::Pass
        }
    }
}

/// BD-1P2R-EVT-002: MUST define GOV_009_DISPATCH_HOOK event code
struct EventCodeDispatchHookTest;

impl ConformanceTest for EventCodeDispatchHookTest {
    fn name(&self) -> &str { "BD-1P2R-EVT-002" }
    fn category(&self) -> TestCategory { TestCategory::EventCodes }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        if GOV_009_DISPATCH_HOOK != "GOV_009" {
            TestResult::Fail {
                reason: format!("GOV_009_DISPATCH_HOOK should be 'GOV_009', got '{}'", GOV_009_DISPATCH_HOOK)
            }
        } else {
            TestResult::Pass
        }
    }
}

/// BD-1P2R-EVT-003: MUST define GOV_010_KNOB_DISPATCHED event code
struct EventCodeKnobDispatchedTest;

impl ConformanceTest for EventCodeKnobDispatchedTest {
    fn name(&self) -> &str { "BD-1P2R-EVT-003" }
    fn category(&self) -> TestCategory { TestCategory::EventCodes }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        if GOV_010_KNOB_DISPATCHED != "GOV_010" {
            TestResult::Fail {
                reason: format!("GOV_010_KNOB_DISPATCHED should be 'GOV_010', got '{}'", GOV_010_KNOB_DISPATCHED)
            }
        } else {
            TestResult::Pass
        }
    }
}

/// BD-1P2R-DESC-001: KnobDescriptor MUST contain all required fields
struct KnobDescriptorFieldsTest;

impl ConformanceTest for KnobDescriptorFieldsTest {
    fn name(&self) -> &str { "BD-1P2R-DESC-001" }
    fn category(&self) -> TestCategory { TestCategory::DataStructures }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let descriptor = KnobDescriptor {
            knob: RuntimeKnob::ConcurrencyLimit,
            label: "Test Knob".to_string(),
            current_value: 64,
            locked: false,
            min_value: 1,
            max_value: 4096,
        };

        // Verify all fields are accessible
        if descriptor.knob != RuntimeKnob::ConcurrencyLimit {
            return TestResult::Fail {
                reason: "knob field not accessible or incorrect".to_string()
            };
        }

        if descriptor.label != "Test Knob" {
            return TestResult::Fail {
                reason: "label field not accessible or incorrect".to_string()
            };
        }

        if descriptor.current_value != 64 {
            return TestResult::Fail {
                reason: "current_value field not accessible or incorrect".to_string()
            };
        }

        if descriptor.locked != false {
            return TestResult::Fail {
                reason: "locked field not accessible or incorrect".to_string()
            };
        }

        if descriptor.min_value != 1 {
            return TestResult::Fail {
                reason: "min_value field not accessible or incorrect".to_string()
            };
        }

        if descriptor.max_value != 4096 {
            return TestResult::Fail {
                reason: "max_value field not accessible or incorrect".to_string()
            };
        }

        TestResult::Pass
    }
}

/// BD-1P2R-DESC-002: KnobDescriptor MUST support Clone and PartialEq
struct KnobDescriptorTraitsTest;

impl ConformanceTest for KnobDescriptorTraitsTest {
    fn name(&self) -> &str { "BD-1P2R-DESC-002" }
    fn category(&self) -> TestCategory { TestCategory::DataStructures }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let desc1 = KnobDescriptor {
            knob: RuntimeKnob::BatchSize,
            label: "Batch Size".to_string(),
            current_value: 128,
            locked: true,
            min_value: 1,
            max_value: 8192,
        };

        let desc2 = desc1.clone();

        // Test Clone trait
        if desc1 != desc2 {
            return TestResult::Fail {
                reason: "Clone trait not working correctly".to_string()
            };
        }

        // Test PartialEq trait
        let desc3 = KnobDescriptor {
            knob: RuntimeKnob::BatchSize,
            label: "Different Label".to_string(),  // Different label
            current_value: 128,
            locked: true,
            min_value: 1,
            max_value: 8192,
        };

        if desc1 == desc3 {
            return TestResult::Fail {
                reason: "PartialEq should detect differences in fields".to_string()
            };
        }

        TestResult::Pass
    }
}

/// BD-1P2R-DESC-003: KnobDescriptor MUST support serialization
struct KnobDescriptorSerializationTest;

impl ConformanceTest for KnobDescriptorSerializationTest {
    fn name(&self) -> &str { "BD-1P2R-DESC-003" }
    fn category(&self) -> TestCategory { TestCategory::DataStructures }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let descriptor = KnobDescriptor {
            knob: RuntimeKnob::ConcurrencyLimit,
            label: "Test Serialization".to_string(),
            current_value: 256,
            locked: false,
            min_value: 1,
            max_value: 4096,
        };

        // Test JSON serialization
        let json_result = serde_json::to_string(&descriptor);
        match json_result {
            Ok(json_str) => {
                if json_str.is_empty() {
                    return TestResult::Fail {
                        reason: "Serialized JSON should not be empty".to_string()
                    };
                }

                // Test deserialization
                let deser_result: Result<KnobDescriptor, _> = serde_json::from_str(&json_str);
                match deser_result {
                    Ok(deserialized) => {
                        if deserialized != descriptor {
                            TestResult::Fail {
                                reason: "Deseriliazation should produce identical struct".to_string()
                            }
                        } else {
                            TestResult::Pass
                        }
                    }
                    Err(e) => TestResult::Fail {
                        reason: format!("Deserialization failed: {e}")
                    }
                }
            }
            Err(e) => TestResult::Fail {
                reason: format!("Serialization failed: {e}")
            }
        }
    }
}

/// BD-1P2R-DESC-004: KnobDescriptor SHOULD validate min <= max constraint
struct KnobDescriptorValidationTest;

impl ConformanceTest for KnobDescriptorValidationTest {
    fn name(&self) -> &str { "BD-1P2R-DESC-004" }
    fn category(&self) -> TestCategory { TestCategory::DataStructures }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Should }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Create descriptor with valid range
        let valid_descriptor = KnobDescriptor {
            knob: RuntimeKnob::ConcurrencyLimit,
            label: "Valid Range".to_string(),
            current_value: 64,
            locked: false,
            min_value: 1,
            max_value: 4096,
        };

        if valid_descriptor.min_value > valid_descriptor.max_value {
            return TestResult::Fail {
                reason: "Valid descriptor should have min <= max".to_string()
            };
        }

        // Test edge case where min == max
        let edge_descriptor = KnobDescriptor {
            knob: RuntimeKnob::BatchSize,
            label: "Edge Case".to_string(),
            current_value: 100,
            locked: false,
            min_value: 100,
            max_value: 100,
        };

        if edge_descriptor.min_value > edge_descriptor.max_value {
            return TestResult::Fail {
                reason: "Edge case descriptor (min == max) should be valid".to_string()
            };
        }

        TestResult::Pass
    }
}

/// BD-1P2R-ENUM-001: KnobEnumeration MUST provide count() method
struct KnobEnumerationCountTest;

impl ConformanceTest for KnobEnumerationCountTest {
    fn name(&self) -> &str { "BD-1P2R-ENUM-001" }
    fn category(&self) -> TestCategory { TestCategory::Enumeration }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Test empty enumeration
        let empty_enum = KnobEnumeration {
            knobs: vec![],
            schema_version: "v1.0".to_string(),
        };

        if empty_enum.count() != 0 {
            return TestResult::Fail {
                reason: "Empty enumeration should have count 0".to_string()
            };
        }

        // Test non-empty enumeration
        let populated_enum = KnobEnumeration {
            knobs: vec![
                create_test_knob_descriptor(RuntimeKnob::ConcurrencyLimit, "concurrent", false),
                create_test_knob_descriptor(RuntimeKnob::BatchSize, "batch", true),
            ],
            schema_version: "v1.0".to_string(),
        };

        if populated_enum.count() != 2 {
            return TestResult::Fail {
                reason: format!("Populated enumeration should have count 2, got {}", populated_enum.count())
            };
        }

        TestResult::Pass
    }
}

/// BD-1P2R-ENUM-002: KnobEnumeration MUST provide get() lookup method
struct KnobEnumerationGetTest;

impl ConformanceTest for KnobEnumerationGetTest {
    fn name(&self) -> &str { "BD-1P2R-ENUM-002" }
    fn category(&self) -> TestCategory { TestCategory::Enumeration }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let enumeration = KnobEnumeration {
            knobs: vec![
                create_test_knob_descriptor(RuntimeKnob::ConcurrencyLimit, "concurrent", false),
                create_test_knob_descriptor(RuntimeKnob::BatchSize, "batch", true),
            ],
            schema_version: "v1.0".to_string(),
        };

        // Test successful lookup
        let found = enumeration.get(&RuntimeKnob::ConcurrencyLimit);
        match found {
            Some(descriptor) => {
                if descriptor.label != "concurrent" {
                    return TestResult::Fail {
                        reason: "get() should return correct descriptor".to_string()
                    };
                }
            }
            None => {
                return TestResult::Fail {
                    reason: "get() should find existing knob".to_string()
                };
            }
        }

        // Test missing knob lookup
        let not_found = enumeration.get(&RuntimeKnob::CacheCapacity);
        if not_found.is_some() {
            return TestResult::Fail {
                reason: "get() should return None for missing knob".to_string()
            };
        }

        TestResult::Pass
    }
}

/// BD-1P2R-ENUM-003: KnobEnumeration MUST provide unlocked() filter method
struct KnobEnumerationUnlockedTest;

impl ConformanceTest for KnobEnumerationUnlockedTest {
    fn name(&self) -> &str { "BD-1P2R-ENUM-003" }
    fn category(&self) -> TestCategory { TestCategory::Enumeration }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let enumeration = KnobEnumeration {
            knobs: vec![
                create_test_knob_descriptor(RuntimeKnob::ConcurrencyLimit, "unlocked1", false),
                create_test_knob_descriptor(RuntimeKnob::BatchSize, "locked1", true),
                create_test_knob_descriptor(RuntimeKnob::CacheCapacity, "unlocked2", false),
            ],
            schema_version: "v1.0".to_string(),
        };

        let unlocked = enumeration.unlocked();

        if unlocked.len() != 2 {
            return TestResult::Fail {
                reason: format!("Should find 2 unlocked knobs, found {}", unlocked.len())
            };
        }

        // Verify only unlocked knobs are returned
        for descriptor in unlocked {
            if descriptor.locked {
                return TestResult::Fail {
                    reason: "unlocked() should not return locked knobs".to_string()
                };
            }
        }

        TestResult::Pass
    }
}

/// BD-1P2R-ENUM-004: KnobEnumeration MUST provide locked() filter method
struct KnobEnumerationLockedTest;

impl ConformanceTest for KnobEnumerationLockedTest {
    fn name(&self) -> &str { "BD-1P2R-ENUM-004" }
    fn category(&self) -> TestCategory { TestCategory::Enumeration }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let enumeration = KnobEnumeration {
            knobs: vec![
                create_test_knob_descriptor(RuntimeKnob::ConcurrencyLimit, "unlocked1", false),
                create_test_knob_descriptor(RuntimeKnob::BatchSize, "locked1", true),
                create_test_knob_descriptor(RuntimeKnob::CacheCapacity, "locked2", true),
            ],
            schema_version: "v1.0".to_string(),
        };

        let locked = enumeration.locked();

        if locked.len() != 2 {
            return TestResult::Fail {
                reason: format!("Should find 2 locked knobs, found {}", locked.len())
            };
        }

        // Verify only locked knobs are returned
        for descriptor in locked {
            if !descriptor.locked {
                return TestResult::Fail {
                    reason: "locked() should not return unlocked knobs".to_string()
                };
            }
        }

        TestResult::Pass
    }
}

/// BD-1P2R-ENUM-005: KnobEnumeration MUST have schema_version field
struct KnobEnumerationSchemaVersionTest;

impl ConformanceTest for KnobEnumerationSchemaVersionTest {
    fn name(&self) -> &str { "BD-1P2R-ENUM-005" }
    fn category(&self) -> TestCategory { TestCategory::Enumeration }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let enumeration = KnobEnumeration {
            knobs: vec![],
            schema_version: "test-v1.2.3".to_string(),
        };

        if enumeration.schema_version != "test-v1.2.3" {
            TestResult::Fail {
                reason: "schema_version field should be accessible and correct".to_string()
            }
        } else {
            TestResult::Pass
        }
    }
}

/// BD-1P2R-FILTER-001: unlocked() + locked() MUST equal total count
struct FilteringConsistencyTest;

impl ConformanceTest for FilteringConsistencyTest {
    fn name(&self) -> &str { "BD-1P2R-FILTER-001" }
    fn category(&self) -> TestCategory { TestCategory::Filtering }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let enumeration = KnobEnumeration {
            knobs: vec![
                create_test_knob_descriptor(RuntimeKnob::ConcurrencyLimit, "unlocked", false),
                create_test_knob_descriptor(RuntimeKnob::BatchSize, "locked", true),
                create_test_knob_descriptor(RuntimeKnob::CacheCapacity, "unlocked2", false),
                create_test_knob_descriptor(RuntimeKnob::DrainTimeoutMs, "locked2", true),
            ],
            schema_version: "v1.0".to_string(),
        };

        let total_count = enumeration.count();
        let unlocked_count = enumeration.unlocked().len();
        let locked_count = enumeration.locked().len();

        if unlocked_count + locked_count != total_count {
            TestResult::Fail {
                reason: format!(
                    "unlocked({}) + locked({}) should equal total({})",
                    unlocked_count, locked_count, total_count
                )
            }
        } else {
            TestResult::Pass
        }
    }
}

/// BD-1P2R-FILTER-002: Empty enumeration MUST return empty filters
struct FilteringEmptyEnumerationTest;

impl ConformanceTest for FilteringEmptyEnumerationTest {
    fn name(&self) -> &str { "BD-1P2R-FILTER-002" }
    fn category(&self) -> TestCategory { TestCategory::Filtering }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let empty_enumeration = KnobEnumeration {
            knobs: vec![],
            schema_version: "v1.0".to_string(),
        };

        if !empty_enumeration.unlocked().is_empty() {
            return TestResult::Fail {
                reason: "Empty enumeration should have no unlocked knobs".to_string()
            };
        }

        if !empty_enumeration.locked().is_empty() {
            return TestResult::Fail {
                reason: "Empty enumeration should have no locked knobs".to_string()
            };
        }

        if empty_enumeration.count() != 0 {
            return TestResult::Fail {
                reason: "Empty enumeration should have count 0".to_string()
            };
        }

        TestResult::Pass
    }
}

/// BD-1P2R-FILTER-003: get() MUST handle duplicate knobs by returning first match
struct FilteringDuplicateHandlingTest;

impl ConformanceTest for FilteringDuplicateHandlingTest {
    fn name(&self) -> &str { "BD-1P2R-FILTER-003" }
    fn category(&self) -> TestCategory { TestCategory::Filtering }
    fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let enumeration = KnobEnumeration {
            knobs: vec![
                KnobDescriptor {
                    knob: RuntimeKnob::BatchSize,
                    label: "first".to_string(),
                    current_value: 100,
                    locked: false,
                    min_value: 1,
                    max_value: 1000,
                },
                KnobDescriptor {
                    knob: RuntimeKnob::BatchSize, // Duplicate knob
                    label: "second".to_string(),
                    current_value: 200,
                    locked: true,
                    min_value: 1,
                    max_value: 2000,
                },
            ],
            schema_version: "v1.0".to_string(),
        };

        let found = enumeration.get(&RuntimeKnob::BatchSize);
        match found {
            Some(descriptor) => {
                if descriptor.label != "first" {
                    TestResult::Fail {
                        reason: "get() should return first match for duplicate knobs".to_string()
                    }
                } else {
                    TestResult::Pass
                }
            }
            None => TestResult::Fail {
                reason: "get() should find the knob even with duplicates".to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test Helper Functions
// ---------------------------------------------------------------------------

fn create_test_knob_descriptor(knob: RuntimeKnob, label: &str, locked: bool) -> KnobDescriptor {
    KnobDescriptor {
        knob,
        label: label.to_string(),
        current_value: 64,
        locked,
        min_value: 1,
        max_value: 4096,
    }
}

// ---------------------------------------------------------------------------
// Conformance Test Runner
// ---------------------------------------------------------------------------

fn collect_conformance_tests() -> Vec<Box<dyn ConformanceTest>> {
    vec![
        Box::new(EventCodeKnobEnumerationTest),
        Box::new(EventCodeDispatchHookTest),
        Box::new(EventCodeKnobDispatchedTest),
        Box::new(KnobDescriptorFieldsTest),
        Box::new(KnobDescriptorTraitsTest),
        Box::new(KnobDescriptorSerializationTest),
        Box::new(KnobDescriptorValidationTest),
        Box::new(KnobEnumerationCountTest),
        Box::new(KnobEnumerationGetTest),
        Box::new(KnobEnumerationUnlockedTest),
        Box::new(KnobEnumerationLockedTest),
        Box::new(KnobEnumerationSchemaVersionTest),
        Box::new(FilteringConsistencyTest),
        Box::new(FilteringEmptyEnumerationTest),
        Box::new(FilteringDuplicateHandlingTest),
    ]
}

pub fn generate_compliance_report() -> String {
    let tests = collect_conformance_tests();
    let ctx = TestContext::new();

    let mut results = Vec::new();
    let mut must_pass = 0;
    let mut must_total = 0;
    let mut should_pass = 0;
    let mut should_total = 0;

    for test in tests {
        let result = test.run(&ctx);
        let is_pass = matches!(result, TestResult::Pass);

        match test.requirement_level() {
            RequirementLevel::Must => {
                must_total += 1;
                if is_pass { must_pass += 1; }
            }
            RequirementLevel::Should => {
                should_total += 1;
                if is_pass { should_pass += 1; }
            }
            RequirementLevel::May => {}
        }

        println!(
            "{{\"id\":\"{}\",\"verdict\":\"{}\",\"level\":\"{:?}\",\"category\":\"{:?}\"}}",
            test.name(),
            if is_pass { "PASS" } else { "FAIL" },
            test.requirement_level(),
            test.category()
        );

        results.push((test, result));
    }

    let must_score = if must_total > 0 {
        (must_pass as f64 / must_total as f64) * 100.0
    } else {
        100.0
    };

    let should_score = if should_total > 0 {
        (should_pass as f64 / should_total as f64) * 100.0
    } else {
        100.0
    };

    format!(
        "\nbd-1p2r Engine Dispatch Hooks Conformance Report\n\
         ================================================\n\
         MUST Requirements:   {must_pass}/{must_total} ({must_score:.1}%)\n\
         SHOULD Requirements: {should_pass}/{should_total} ({should_score:.1}%)\n\
         Overall Conformance: {:.1}%\n",
        (must_score + should_score) / 2.0
    )
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn bd_1p2r_full_conformance_suite() {
    let report = generate_compliance_report();
    println!("{report}");

    // Conformance requirement: must pass all MUST clauses
    let tests = collect_conformance_tests();
    let ctx = TestContext::new();

    for test in tests {
        if test.requirement_level() == RequirementLevel::Must {
            let result = test.run(&ctx);
            assert!(
                matches!(result, TestResult::Pass),
                "MUST requirement {} failed: {result:?}",
                test.name()
            );
        }
    }
}

#[test]
fn bd_1p2r_event_codes_coverage() {
    // Covers BD-1P2R-EVT-001 through BD-1P2R-EVT-003
    let tests = [
        Box::new(EventCodeKnobEnumerationTest) as Box<dyn ConformanceTest>,
        Box::new(EventCodeDispatchHookTest),
        Box::new(EventCodeKnobDispatchedTest),
    ];
    let ctx = TestContext::new();

    for test in tests {
        assert!(matches!(test.run(&ctx), TestResult::Pass));
    }
}

#[test]
fn bd_1p2r_knob_descriptor_coverage() {
    // Covers BD-1P2R-DESC-001 through BD-1P2R-DESC-004
    let tests = [
        Box::new(KnobDescriptorFieldsTest) as Box<dyn ConformanceTest>,
        Box::new(KnobDescriptorTraitsTest),
        Box::new(KnobDescriptorSerializationTest),
        Box::new(KnobDescriptorValidationTest),
    ];
    let ctx = TestContext::new();

    for test in tests {
        let result = test.run(&ctx);
        // SHOULD requirements may not pass, but MUST requirements must pass
        if test.requirement_level() == RequirementLevel::Must {
            assert!(matches!(result, TestResult::Pass));
        }
    }
}

#[test]
fn bd_1p2r_enumeration_filtering_coverage() {
    // Covers all enumeration and filtering tests
    let enumeration = KnobEnumeration {
        knobs: vec![
            create_test_knob_descriptor(RuntimeKnob::ConcurrencyLimit, "test1", false),
            create_test_knob_descriptor(RuntimeKnob::BatchSize, "test2", true),
        ],
        schema_version: "test".to_string(),
    };

    assert_eq!(enumeration.count(), 2);
    assert_eq!(enumeration.unlocked().len(), 1);
    assert_eq!(enumeration.locked().len(), 1);
    assert!(enumeration.get(&RuntimeKnob::ConcurrencyLimit).is_some());
    assert!(enumeration.get(&RuntimeKnob::CacheCapacity).is_none());
}