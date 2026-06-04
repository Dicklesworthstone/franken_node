#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use frankenengine_node::migration::rewrite_suggestion_engine::{
    generate_rollback_plan_at, generate_suggestions, generate_suggestions_from_scan,
    produce_report, RewriteApiUsage, RewriteCategory, RewriteRiskLevel, RewriteSuggestionReport,
};
use frankenengine_node::supply_chain::project_scanner::{
    compute_readiness, ApiUsage, DependencyRisk, ProjectScanReport, RiskDistribution, RiskLevel,
    ScanSummary,
};

// Size limits for bounded fuzzing
const MAX_API_USAGES: usize = 50;
const MAX_STRING_LEN: usize = 1024;
const MAX_FILE_PATH_LEN: usize = 512;
const MAX_LINE_NUMBER: u64 = 1_000_000;
const MAX_DEPENDENCIES: usize = 20;
const MAX_RISK_LEVELS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
enum FuzzRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl From<FuzzRiskLevel> for RiskLevel {
    fn from(fuzz: FuzzRiskLevel) -> Self {
        match fuzz {
            FuzzRiskLevel::Low => Self::Low,
            FuzzRiskLevel::Medium => Self::Medium,
            FuzzRiskLevel::High => Self::High,
            FuzzRiskLevel::Critical => Self::Critical,
        }
    }
}

fn rewrite_risk_priority(risk_level: RewriteRiskLevel) -> u8 {
    match risk_level {
        RewriteRiskLevel::Critical => 0,
        RewriteRiskLevel::High => 1,
        RewriteRiskLevel::Medium => 2,
        RewriteRiskLevel::Low => 3,
    }
}

/// Fuzzable API usage with bounded strings
#[derive(Debug, Clone, Arbitrary)]
struct FuzzApiUsage {
    #[arbitrary(with = bounded_api_family)]
    api_family: String,
    #[arbitrary(with = bounded_api_name)]
    api_name: String,
    #[arbitrary(with = bounded_source_file)]
    source_file: String,
    #[arbitrary(with = bounded_line_number)]
    line_number: Option<u64>,
    #[arbitrary(with = bounded_band)]
    band: Option<String>,
    #[arbitrary(with = bounded_impl_status)]
    impl_status: Option<String>,
    risk_level: FuzzRiskLevel,
}

impl From<FuzzApiUsage> for ApiUsage {
    fn from(fuzz: FuzzApiUsage) -> Self {
        Self {
            api_family: fuzz.api_family,
            api_name: fuzz.api_name,
            source_file: fuzz.source_file,
            line_number: fuzz.line_number,
            band: fuzz.band,
            impl_status: fuzz.impl_status,
            risk_level: fuzz.risk_level.into(),
        }
    }
}

impl From<FuzzApiUsage> for RewriteApiUsage {
    fn from(fuzz: FuzzApiUsage) -> Self {
        Self {
            api_family: fuzz.api_family,
            api_name: fuzz.api_name,
            source_file: fuzz.source_file,
            line_number: fuzz.line_number,
            risk_level: RiskLevel::from(fuzz.risk_level).into(),
        }
    }
}

/// Fuzzable dependency info
#[derive(Debug, Clone, Arbitrary)]
struct FuzzDependencyInfo {
    #[arbitrary(with = bounded_package_name)]
    name: String,
    #[arbitrary(with = bounded_optional_version)]
    version: Option<String>,
    has_native_addon: bool,
    risk_level: FuzzRiskLevel,
    #[arbitrary(with = bounded_optional_notes)]
    notes: Option<String>,
}

impl From<FuzzDependencyInfo> for DependencyRisk {
    fn from(fuzz: FuzzDependencyInfo) -> Self {
        Self {
            name: fuzz.name,
            version: fuzz.version,
            has_native_addon: fuzz.has_native_addon,
            risk_level: fuzz.risk_level.into(),
            notes: fuzz.notes,
        }
    }
}

/// Fuzzable project scan report
#[derive(Debug, Clone, Arbitrary)]
struct FuzzProjectScanReport {
    #[arbitrary(with = bounded_project_name)]
    project_name: String,
    #[arbitrary(with = bounded_timestamp)]
    scan_timestamp: String,
    #[arbitrary(with = bounded_api_usages)]
    api_usage: Vec<FuzzApiUsage>,
    #[arbitrary(with = bounded_dependencies)]
    dependencies: Vec<FuzzDependencyInfo>,
}

impl From<FuzzProjectScanReport> for ProjectScanReport {
    fn from(fuzz: FuzzProjectScanReport) -> Self {
        let api_usage: Vec<ApiUsage> = fuzz.api_usage.into_iter().map(Into::into).collect();
        let dependencies: Vec<DependencyRisk> =
            fuzz.dependencies.into_iter().map(Into::into).collect();
        let mut risk_distribution = RiskDistribution::default();
        for usage in &api_usage {
            risk_distribution.increment(usage.risk_level);
        }
        for dependency in &dependencies {
            if dependency.risk_level == RiskLevel::Critical {
                risk_distribution.increment(RiskLevel::Critical);
            }
        }
        let migration_readiness = compute_readiness(&risk_distribution);

        Self {
            project: fuzz.project_name,
            scan_timestamp: fuzz.scan_timestamp,
            summary: ScanSummary {
                total_apis_detected: api_usage.len() as u64,
                risk_distribution,
                migration_readiness,
            },
            api_usage,
            dependencies,
            recommendations: Vec::new(),
        }
    }
}

/// Operations to test on the rewrite suggestion engine
#[derive(Debug, Clone, Arbitrary)]
enum RewriteOperation {
    GenerateSuggestionsFromUsages {
        #[arbitrary(with = bounded_api_usages)]
        usages: Vec<FuzzApiUsage>,
    },
    GenerateSuggestionsFromScan {
        scan_report: FuzzProjectScanReport,
    },
    GenerateRollbackPlan {
        #[arbitrary(with = bounded_api_usages)]
        usages: Vec<FuzzApiUsage>,
        #[arbitrary(with = bounded_project_name)]
        project: String,
        #[arbitrary(with = bounded_timestamp)]
        timestamp: String,
    },
    GenerateFullReport {
        scan_report: FuzzProjectScanReport,
    },
    TestSerialization {
        #[arbitrary(with = bounded_api_usages)]
        usages: Vec<FuzzApiUsage>,
        #[arbitrary(with = bounded_project_name)]
        project: String,
    },
    TestRiskLevelConversion {
        #[arbitrary(with = bounded_risk_levels)]
        risk_levels: Vec<FuzzRiskLevel>,
    },
    TestCategoryAssignment {
        #[arbitrary(with = bounded_api_usages)]
        usages: Vec<FuzzApiUsage>,
    },
}

/// Complete fuzz input
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    #[arbitrary(with = bounded_rewrite_operations)]
    operations: Vec<RewriteOperation>,
}

// Bounded arbitrary helpers

fn bounded_api_family(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=8)?;
    Ok(match choice {
        0 => String::new(),                        // Empty
        1 => "fs".to_string(),                     // Valid family
        2 => "crypto".to_string(),                 // Another valid family
        3 => "network".to_string(),                // Yet another
        4 => "\x00null".to_string(),               // Null byte
        5 => "family\nwith\nnewlines".to_string(), // Newlines
        6 => "family\twith\ttabs".to_string(),     // Tabs
        7 => "a".repeat(500),                      // Very long
        8 => {
            let len = u.int_in_range(0..=MAX_STRING_LEN)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_api_name(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=8)?;
    Ok(match choice {
        0 => String::new(),             // Empty
        1 => "readFile".to_string(),    // Valid name
        2 => "writeFile".to_string(),   // Another valid name
        3 => "createHash".to_string(),  // Crypto API
        4 => "api\x00name".to_string(), // Null byte
        5 => "api name".to_string(),    // Space
        6 => "api/name".to_string(),    // Slash
        7 => "a".repeat(300),           // Very long
        8 => {
            let len = u.int_in_range(0..=MAX_STRING_LEN)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_source_file(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=10)?;
    Ok(match choice {
        0 => String::new(),                            // Empty
        1 => "src/main.js".to_string(),                // Valid path
        2 => "lib/utils.ts".to_string(),               // TypeScript
        3 => "/absolute/path.js".to_string(),          // Absolute
        4 => "../../../etc/passwd".to_string(),        // Path traversal
        5 => "file\x00name".to_string(),               // Null byte
        6 => "file name.js".to_string(),               // Space
        7 => "file\\with\\backslashes.js".to_string(), // Windows path
        8 => "file\nwith\nnewlines.js".to_string(),    // Newlines
        9 => "a".repeat(1000),                         // Very long
        10 => {
            let len = u.int_in_range(0..=MAX_FILE_PATH_LEN)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_line_number(u: &mut Unstructured) -> arbitrary::Result<Option<u64>> {
    if u.arbitrary::<bool>()? {
        Ok(Some(u.int_in_range(1..=MAX_LINE_NUMBER)?))
    } else {
        Ok(None)
    }
}

fn bounded_band(u: &mut Unstructured) -> arbitrary::Result<Option<String>> {
    if !u.arbitrary::<bool>()? {
        return Ok(None);
    }

    let choice = u.int_in_range(0..=5)?;
    Ok(Some(match choice {
        0 => "core".to_string(),
        1 => "high-value".to_string(),
        2 => "edge".to_string(),
        3 => "unknown".to_string(),
        4 => String::new(),
        5 => {
            let len = u.int_in_range(0..=50)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    }))
}

fn bounded_impl_status(u: &mut Unstructured) -> arbitrary::Result<Option<String>> {
    if !u.arbitrary::<bool>()? {
        return Ok(None);
    }

    let choice = u.int_in_range(0..=5)?;
    Ok(Some(match choice {
        0 => "native".to_string(),
        1 => "polyfill".to_string(),
        2 => "bridge".to_string(),
        3 => "unsupported".to_string(),
        4 => String::new(),
        5 => {
            let len = u.int_in_range(0..=50)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    }))
}

fn bounded_package_name(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=6)?;
    Ok(match choice {
        0 => String::new(),                          // Empty
        1 => "lodash".to_string(),                   // Valid package
        2 => "@babel/core".to_string(),              // Scoped package
        3 => "package-with-dashes".to_string(),      // Dashes
        4 => "package_with_underscores".to_string(), // Underscores
        5 => "package\x00null".to_string(),          // Null byte
        6 => {
            let len = u.int_in_range(0..=100)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_version(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=6)?;
    Ok(match choice {
        0 => String::new(),              // Empty
        1 => "1.0.0".to_string(),        // Valid semver
        2 => "^1.2.3".to_string(),       // Caret range
        3 => "~1.2.3".to_string(),       // Tilde range
        4 => "latest".to_string(),       // Tag
        5 => "1.0.0-beta.1".to_string(), // Prerelease
        6 => {
            let len = u.int_in_range(0..=50)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_optional_version(u: &mut Unstructured) -> arbitrary::Result<Option<String>> {
    if u.arbitrary::<bool>()? {
        Ok(Some(bounded_version(u)?))
    } else {
        Ok(None)
    }
}

fn bounded_optional_notes(u: &mut Unstructured) -> arbitrary::Result<Option<String>> {
    if u.arbitrary::<bool>()? {
        let len = u.int_in_range(0..=200)?;
        let bytes = u.bytes(len)?;
        Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
    } else {
        Ok(None)
    }
}

fn bounded_project_name(u: &mut Unstructured) -> arbitrary::Result<String> {
    bounded_package_name(u) // Same logic
}

fn bounded_timestamp(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=5)?;
    Ok(match choice {
        0 => String::new(),                      // Empty
        1 => "2026-05-22T16:10:00Z".to_string(), // Valid ISO
        2 => "2026-05-22 16:10:00".to_string(),  // Non-ISO format
        3 => "invalid-timestamp".to_string(),    // Invalid
        4 => "1970-01-01T00:00:00Z".to_string(), // Epoch
        5 => {
            let len = u.int_in_range(0..=50)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_api_usages(u: &mut Unstructured) -> arbitrary::Result<Vec<FuzzApiUsage>> {
    let len = u.int_in_range(0..=MAX_API_USAGES)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fn bounded_dependencies(u: &mut Unstructured) -> arbitrary::Result<Vec<FuzzDependencyInfo>> {
    let len = u.int_in_range(0..=MAX_DEPENDENCIES)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fn bounded_risk_levels(u: &mut Unstructured) -> arbitrary::Result<Vec<FuzzRiskLevel>> {
    let len = u.int_in_range(0..=MAX_RISK_LEVELS)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fn bounded_rewrite_operations(u: &mut Unstructured) -> arbitrary::Result<Vec<RewriteOperation>> {
    let len = u.int_in_range(1..=8)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fuzz_target!(|data: &[u8]| {
    // Input size guard to prevent OOM
    if data.len() > 200_000 {
        return;
    }

    let input: FuzzInput = match Unstructured::new(data).arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Invalid input, skip silently
    };

    // Track state for invariant checking
    let mut serialization_attempts = 0;
    let mut successful_serializations = 0;

    // Execute fuzzed operations
    for op in input.operations {
        match op {
            RewriteOperation::GenerateSuggestionsFromUsages { usages } => {
                let rewrite_usages: Vec<RewriteApiUsage> =
                    usages.into_iter().map(|u| u.into()).collect();
                let suggestions = generate_suggestions(&rewrite_usages);

                // Verify suggestion properties
                for suggestion in &suggestions {
                    // Risk levels should be valid
                    assert!(
                        matches!(
                            suggestion.risk_level,
                            RewriteRiskLevel::Critical
                                | RewriteRiskLevel::High
                                | RewriteRiskLevel::Medium
                                | RewriteRiskLevel::Low
                        ),
                        "Risk level should be valid enum variant"
                    );

                    // Categories should be valid
                    assert!(
                        matches!(
                            suggestion.category,
                            RewriteCategory::DirectReplacement
                                | RewriteCategory::AdapterNeeded
                                | RewriteCategory::RemovalNeeded
                                | RewriteCategory::ManualReview
                        ),
                        "Category should be valid enum variant"
                    );

                    // Line numbers should be reasonable if present
                    if let Some(line_num) = suggestion.line_number {
                        assert!(line_num > 0, "Line numbers should be positive");
                        assert!(
                            line_num <= MAX_LINE_NUMBER,
                            "Line numbers should be reasonable"
                        );
                    }

                    // Descriptions should not be empty for valid suggestions
                    if !suggestion.api_family.is_empty() && !suggestion.api_name.is_empty() {
                        assert!(
                            !suggestion.description.is_empty(),
                            "Valid suggestions should have descriptions"
                        );
                    }

                    // Before/after code should be different for actual rewrites
                    if suggestion.category == RewriteCategory::DirectReplacement
                        && !suggestion.before.is_empty()
                        && !suggestion.after.is_empty()
                    {
                        assert_ne!(
                            suggestion.before, suggestion.after,
                            "Direct replacement should have different before/after"
                        );
                    }
                }

                // Suggestions should be sorted by risk level priority
                for window in suggestions.windows(2) {
                    let left_priority = rewrite_risk_priority(window[0].risk_level);
                    let right_priority = rewrite_risk_priority(window[1].risk_level);
                    assert!(
                        left_priority <= right_priority,
                        "Suggestions should be sorted by risk level priority"
                    );
                }
            }

            RewriteOperation::GenerateSuggestionsFromScan { scan_report } => {
                let project_scan: ProjectScanReport = scan_report.into();
                let suggestions = generate_suggestions_from_scan(&project_scan);

                // Number of suggestions should not exceed number of API usages
                assert!(
                    suggestions.len() <= project_scan.api_usage.len(),
                    "Suggestions count should not exceed API usage count"
                );

                // Verify suggestions map to actual API usages
                for suggestion in &suggestions {
                    let matches_usage = project_scan.api_usage.iter().any(|usage| {
                        usage.api_family == suggestion.api_family
                            && usage.api_name == suggestion.api_name
                            && usage.source_file == suggestion.source_file
                    });

                    if !suggestion.api_family.is_empty() && !suggestion.api_name.is_empty() {
                        assert!(
                            matches_usage,
                            "Suggestion should correspond to actual API usage"
                        );
                    }
                }
            }

            RewriteOperation::GenerateRollbackPlan {
                usages,
                project,
                timestamp,
            } => {
                let rewrite_usages: Vec<RewriteApiUsage> =
                    usages.into_iter().map(|u| u.into()).collect();
                let suggestions = generate_suggestions(&rewrite_usages);
                let rollback_plan = generate_rollback_plan_at(&suggestions, &project, &timestamp);

                // Verify rollback plan properties
                assert_eq!(rollback_plan.project, project, "Project name should match");
                assert_eq!(
                    rollback_plan.generated_at, timestamp,
                    "Timestamp should match"
                );
                assert_eq!(
                    rollback_plan.suggestion_count as usize,
                    suggestions.len(),
                    "Suggestion count should match"
                );

                // Category counts should sum to total suggestions
                let category_sum: u64 = rollback_plan.categories.values().sum();
                assert_eq!(
                    category_sum, rollback_plan.suggestion_count,
                    "Category counts should sum to total"
                );

                // Affected files should be unique and non-empty for valid suggestions
                let mut unique_files = std::collections::HashSet::new();
                for file in &rollback_plan.affected_files {
                    unique_files.insert(file);
                }
                assert_eq!(
                    unique_files.len(),
                    rollback_plan.affected_files.len(),
                    "Affected files should be unique"
                );

                // Rollback commands should have valid structure
                for command in &rollback_plan.rollback_commands {
                    if !command.command.is_empty() {
                        assert!(
                            !command.description.is_empty(),
                            "Non-empty commands should have descriptions"
                        );
                    }
                }
            }

            RewriteOperation::GenerateFullReport { scan_report } => {
                let project_scan: ProjectScanReport = scan_report.into();
                let report = produce_report(&project_scan);

                // Verify report structure
                assert_eq!(
                    report.schema_version, "franken_node/migration/rewrite_suggestion_report/v1",
                    "Schema version should be correct"
                );
                assert_eq!(
                    report.project, project_scan.project,
                    "Project name should match"
                );

                // Report should include all components
                assert_eq!(
                    report.suggestions.len(),
                    report.rollback_plan.suggestion_count as usize,
                    "Suggestion counts should match between report and rollback plan"
                );

                // Summary should be consistent
                assert_eq!(
                    report.summary.total_suggestions,
                    report.suggestions.len() as u64,
                    "Total suggestions should match the suggestions vector"
                );

                // Category breakdown should sum to total
                let category_total = report.summary.by_category.values().sum::<u64>();
                assert_eq!(
                    category_total, report.summary.total_suggestions,
                    "Category breakdown should sum to total"
                );
            }

            RewriteOperation::TestSerialization { usages, project } => {
                serialization_attempts += 1;

                let rewrite_usages: Vec<RewriteApiUsage> =
                    usages.into_iter().map(|u| u.into()).collect();
                let suggestions = generate_suggestions(&rewrite_usages);
                let rollback_plan =
                    generate_rollback_plan_at(&suggestions, &project, "2026-05-22T16:10:00Z");
                assert_eq!(
                    rollback_plan.suggestion_count as usize,
                    suggestions.len(),
                    "Rollback plan should account for generated suggestions"
                );

                // Create a minimal report
                let risk_distribution = RiskDistribution::default();
                let migration_readiness = compute_readiness(&risk_distribution);
                let scan_report = ProjectScanReport {
                    project: project.clone(),
                    scan_timestamp: "2026-05-22T16:10:00Z".to_string(),
                    summary: ScanSummary {
                        total_apis_detected: 0,
                        risk_distribution,
                        migration_readiness,
                    },
                    api_usage: vec![],
                    dependencies: vec![],
                    recommendations: Vec::new(),
                };

                let report = produce_report(&scan_report);

                // Test JSON serialization
                match serde_json::to_string(&report) {
                    Ok(json_str) => {
                        successful_serializations += 1;

                        // Verify JSON structure
                        assert!(!json_str.is_empty(), "Serialized JSON should not be empty");
                        assert!(
                            json_str.contains("schema_version"),
                            "JSON should contain schema version"
                        );
                        assert!(
                            json_str.contains("suggestions"),
                            "JSON should contain suggestions"
                        );
                        assert!(
                            json_str.contains("rollback_plan"),
                            "JSON should contain rollback plan"
                        );

                        // Test deserialization round-trip
                        match serde_json::from_str::<RewriteSuggestionReport>(&json_str) {
                            Ok(deserialized) => {
                                assert_eq!(
                                    report.schema_version, deserialized.schema_version,
                                    "Schema version should survive round-trip"
                                );
                                assert_eq!(
                                    report.project, deserialized.project,
                                    "Project should survive round-trip"
                                );
                                assert_eq!(
                                    report.suggestions.len(),
                                    deserialized.suggestions.len(),
                                    "Suggestion count should survive round-trip"
                                );
                            }
                            Err(_) => {
                                // Deserialization can fail due to invalid string content
                            }
                        }
                    }
                    Err(_) => {
                        // Serialization can fail due to invalid strings
                    }
                }
            }

            RewriteOperation::TestRiskLevelConversion { risk_levels } => {
                // Test risk level conversions
                for risk_level in risk_levels {
                    let source_risk: RiskLevel = risk_level.into();
                    let rewrite_risk: RewriteRiskLevel = source_risk.into();
                    let priority = rewrite_risk_priority(rewrite_risk);

                    // Priority should be in valid range
                    assert!(priority <= 3, "Priority should be 0-3");

                    // Test priority ordering
                    match rewrite_risk {
                        RewriteRiskLevel::Critical => assert_eq!(priority, 0),
                        RewriteRiskLevel::High => assert_eq!(priority, 1),
                        RewriteRiskLevel::Medium => assert_eq!(priority, 2),
                        RewriteRiskLevel::Low => assert_eq!(priority, 3),
                    }

                    // Test round-trip conversion consistency
                    let back_to_original = match rewrite_risk {
                        RewriteRiskLevel::Critical => RiskLevel::Critical,
                        RewriteRiskLevel::High => RiskLevel::High,
                        RewriteRiskLevel::Medium => RiskLevel::Medium,
                        RewriteRiskLevel::Low => RiskLevel::Low,
                    };
                    assert_eq!(
                        source_risk, back_to_original,
                        "Risk level conversion should be consistent"
                    );
                }
            }

            RewriteOperation::TestCategoryAssignment { usages } => {
                let rewrite_usages: Vec<RewriteApiUsage> =
                    usages.into_iter().map(|u| u.into()).collect();
                let suggestions = generate_suggestions(&rewrite_usages);

                // Test category assignment logic
                for suggestion in &suggestions {
                    // Categories should be assigned based on API families/patterns
                    match suggestion.api_family.as_str() {
                        "fs" | "crypto" | "path" => {
                            // Common Node.js APIs should have reasonable categories
                            assert!(
                                matches!(
                                    suggestion.category,
                                    RewriteCategory::DirectReplacement
                                        | RewriteCategory::AdapterNeeded
                                        | RewriteCategory::ManualReview
                                ),
                                "Common APIs should have actionable categories"
                            );
                        }
                        _ => {
                            // Other APIs may have any category including RemovalNeeded
                        }
                    }

                    // High risk items should generally require more attention
                    if suggestion.risk_level == RewriteRiskLevel::Critical {
                        assert!(
                            matches!(
                                suggestion.category,
                                RewriteCategory::ManualReview | RewriteCategory::RemovalNeeded
                            ),
                            "Critical risk items should require manual attention"
                        );
                    }
                }
            }
        }
    }

    // Invariant checks - these must hold regardless of input
    assert!(
        successful_serializations <= serialization_attempts,
        "Successful serializations should not exceed attempts"
    );

    // Test edge cases with extreme inputs
    let empty_usages: Vec<RewriteApiUsage> = vec![];
    let empty_suggestions = generate_suggestions(&empty_usages);
    assert!(
        empty_suggestions.is_empty(),
        "Empty usages should produce empty suggestions"
    );

    let empty_rollback =
        generate_rollback_plan_at(&empty_suggestions, "test", "2026-01-01T00:00:00Z");
    assert_eq!(
        empty_rollback.suggestion_count, 0,
        "Empty suggestions should produce empty rollback plan"
    );
    assert!(
        empty_rollback.affected_files.is_empty(),
        "Empty rollback should have no affected files"
    );
    assert!(
        empty_rollback.rollback_commands.is_empty(),
        "Empty rollback should have no commands"
    );

    // Test with very long strings
    let long_usage = RewriteApiUsage {
        api_family: "a".repeat(1000),
        api_name: "b".repeat(1000),
        source_file: "c".repeat(1000),
        line_number: Some(999999),
        risk_level: RewriteRiskLevel::High,
    };

    let long_suggestions = generate_suggestions(&[long_usage]);
    assert!(
        !long_suggestions.is_empty(),
        "Long strings should still produce suggestions"
    );

    // Verify the suggestion properties are preserved
    if let Some(suggestion) = long_suggestions.first() {
        assert!(
            suggestion.api_family.len() <= 1000,
            "API family length should be bounded"
        );
        assert!(
            suggestion.api_name.len() <= 1000,
            "API name length should be bounded"
        );
        assert!(
            suggestion.source_file.len() <= 1000,
            "Source file length should be bounded"
        );
    }
});
