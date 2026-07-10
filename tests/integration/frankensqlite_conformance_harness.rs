//! Frankensqlite Adapter Conformance Harness (bd-2pbfa)
//!
//! Replaces ad-hoc scalar assertions with spec-derived conformance testing
//! against the bd-1a1j contract. Loads golden artifacts and verifies the
//! adapter implementation matches the canonical persistence class contract.
//!
//! Pattern: Spec-Derived Testing (Pattern 4) - one test per requirement

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// Import the existing conformance types and adapter
#[path = "frankensqlite_adapter_conformance.rs"]
mod adapter_types;
use adapter_types::*;

/// Conformance test requirement levels for prioritization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,   // Breaking changes are NOT allowed (bd-1a1j contract violations)
    Should, // Breaking changes require major version bump
    May,    // Breaking changes allowed with documentation
}

/// Test categories for organization
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TestCategory {
    CatalogStructure,
    TierMapping,
    ReplaySupport,
    UniquenessConstraints,
    AdapterBehavior,
}

/// Individual conformance test case result
#[derive(Debug, Serialize)]
pub struct ConformanceTestResult {
    pub requirement_id: String,
    pub section: String,
    pub level: RequirementLevel,
    pub description: String,
    pub status: TestStatus,
    pub details: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum TestStatus {
    Pass,
    Fail,
    ExpectedFailure, // Known divergence documented in DISCREPANCIES.md
}

/// Golden file loaders with scrubbing support

fn load_golden_catalog() -> PersistenceClassCatalog {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/goldens/frankensqlite/persistence_class_catalog.json");
    let content =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("Failed to load golden catalog: {}", e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse golden catalog: {}", e))
}

fn load_golden_tier_matrix() -> TierMatrix {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/goldens/frankensqlite/tier_matrix.json");
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to load golden tier matrix: {}", e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse golden tier matrix: {}", e))
}

/// Golden file structures

#[derive(Debug, Deserialize)]
struct PersistenceClassCatalog {
    contract_version: String,
    total_classes: u32,
    tier_distribution: BTreeMap<String, u32>,
    classes: Vec<GoldenPersistenceClass>,
}

#[derive(Debug, Deserialize)]
struct GoldenPersistenceClass {
    domain: String,
    owner_module: String,
    safety_tier: String,
    durability_mode: String,
    tables: Vec<String>,
    replay_support: bool,
    replay_strategy: String,
}

#[derive(Debug, Deserialize)]
struct TierMatrix {
    tier_definitions: BTreeMap<String, TierDefinition>,
    compliance_rules: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct TierDefinition {
    label: String,
    durability_mode: String,
    journal_mode: String,
    synchronous: String,
    requires_replay: bool,
}

/// Conformance test runner

pub fn run_bd1a1j_conformance_suite() -> Vec<ConformanceTestResult> {
    let mut results = Vec::new();

    // Load golden artifacts
    let golden_catalog = load_golden_catalog();
    let golden_matrix = load_golden_tier_matrix();

    // Load actual implementation data
    let actual_classes = canonical_classes();

    // Run conformance tests - one per bd-1a1j requirement
    results.extend(test_catalog_structure(&golden_catalog, &actual_classes));
    results.extend(test_tier_durability_mapping(
        &golden_matrix,
        &actual_classes,
    ));
    results.extend(test_replay_support_requirements(
        &golden_matrix,
        &actual_classes,
    ));
    results.extend(test_uniqueness_constraints(&actual_classes));
    results.extend(test_adapter_behavior());

    results
}

/// BD1A1J-CATALOG-* tests: Catalog structure conformance

fn test_catalog_structure(
    golden: &PersistenceClassCatalog,
    actual: &[PersistenceClass],
) -> Vec<ConformanceTestResult> {
    let mut results = Vec::new();

    // BD1A1J-CATALOG-001: Total class count
    let actual_count = actual.len() as u32;
    results.push(ConformanceTestResult {
        requirement_id: "BD1A1J-CATALOG-001".to_string(),
        section: "catalog_structure".to_string(),
        level: RequirementLevel::Must,
        description: "Catalog MUST contain exactly the specified number of persistence classes"
            .to_string(),
        status: if actual_count == golden.total_classes {
            TestStatus::Pass
        } else {
            TestStatus::Fail
        },
        details: Some(format!(
            "expected: {}, actual: {}",
            golden.total_classes, actual_count
        )),
    });

    // BD1A1J-CATALOG-002: Tier distribution
    let actual_distribution = count_by_tier(actual);
    for (tier, expected_count) in &golden.tier_distribution {
        let actual_count = actual_distribution.get(tier).copied().unwrap_or(0);
        results.push(ConformanceTestResult {
            requirement_id: format!("BD1A1J-CATALOG-002-{}", tier.to_uppercase()),
            section: "catalog_structure".to_string(),
            level: RequirementLevel::Must,
            description: format!("{} MUST have exactly {} classes", tier, expected_count),
            status: if actual_count == *expected_count {
                TestStatus::Pass
            } else {
                TestStatus::Fail
            },
            details: Some(format!(
                "expected: {}, actual: {}",
                expected_count, actual_count
            )),
        });
    }

    results
}

/// BD1A1J-TIER-* tests: Tier-durability mapping conformance

fn test_tier_durability_mapping(
    golden_matrix: &TierMatrix,
    actual: &[PersistenceClass],
) -> Vec<ConformanceTestResult> {
    let mut results = Vec::new();

    for class in actual {
        let tier_key = format!("{:?}", class.safety_tier);
        if let Some(tier_def) = golden_matrix.tier_definitions.get(&tier_key) {
            let expected_durability = &tier_def.durability_mode;
            let actual_durability = format!("{:?}", class.durability_mode);

            results.push(ConformanceTestResult {
                requirement_id: format!("BD1A1J-TIER-{:?}", class.safety_tier),
                section: "tier_mapping".to_string(),
                level: RequirementLevel::Must,
                description: format!(
                    "{:?} classes MUST use {} durability mode",
                    class.safety_tier, expected_durability
                ),
                status: if actual_durability == *expected_durability {
                    TestStatus::Pass
                } else {
                    TestStatus::Fail
                },
                details: Some(format!(
                    "domain: {}, expected: {}, actual: {}",
                    class.domain, expected_durability, actual_durability
                )),
            });
        }
    }

    results
}

/// BD1A1J-REPLAY-* tests: Replay support requirements

fn test_replay_support_requirements(
    golden_matrix: &TierMatrix,
    actual: &[PersistenceClass],
) -> Vec<ConformanceTestResult> {
    let mut results = Vec::new();

    for class in actual {
        let tier_key = format!("{:?}", class.safety_tier);
        if let Some(tier_def) = golden_matrix.tier_definitions.get(&tier_key) {
            let expected_replay = tier_def.requires_replay;
            let actual_replay = class.replay_support;

            let requirement_text = if expected_replay {
                format!("{:?} classes MUST support replay", class.safety_tier)
            } else {
                format!("{:?} classes MUST NOT support replay", class.safety_tier)
            };

            results.push(ConformanceTestResult {
                requirement_id: format!("BD1A1J-REPLAY-{:?}", class.safety_tier),
                section: "replay_support".to_string(),
                level: RequirementLevel::Must,
                description: requirement_text,
                status: if actual_replay == expected_replay {
                    TestStatus::Pass
                } else {
                    TestStatus::Fail
                },
                details: Some(format!(
                    "domain: {}, expected: {}, actual: {}",
                    class.domain, expected_replay, actual_replay
                )),
            });

            // BD1A1J-REPLAY-STRATEGY: Classes with replay support MUST have strategy
            if class.replay_support && class.replay_strategy.is_empty() {
                results.push(ConformanceTestResult {
                    requirement_id: format!("BD1A1J-REPLAY-STRATEGY-{}", class.domain),
                    section: "replay_support".to_string(),
                    level: RequirementLevel::Must,
                    description: "Classes with replay_support=true MUST specify replay strategy"
                        .to_string(),
                    status: TestStatus::Fail,
                    details: Some(format!(
                        "domain: {} has replay_support=true but empty replay_strategy",
                        class.domain
                    )),
                });
            }
        }
    }

    results
}

/// BD1A1J-UNIQUE-* tests: Uniqueness constraints

fn test_uniqueness_constraints(actual: &[PersistenceClass]) -> Vec<ConformanceTestResult> {
    let mut results = Vec::new();

    // BD1A1J-UNIQUE-001: Unique domain names
    let domains: Vec<&str> = actual.iter().map(|c| c.domain.as_str()).collect();
    let unique_domains: BTreeSet<&str> = domains.iter().copied().collect();
    results.push(ConformanceTestResult {
        requirement_id: "BD1A1J-UNIQUE-001".to_string(),
        section: "uniqueness_constraints".to_string(),
        level: RequirementLevel::Must,
        description: "Domain names MUST be unique across all persistence classes".to_string(),
        status: if domains.len() == unique_domains.len() {
            TestStatus::Pass
        } else {
            TestStatus::Fail
        },
        details: Some(format!(
            "total domains: {}, unique domains: {}",
            domains.len(),
            unique_domains.len()
        )),
    });

    // BD1A1J-UNIQUE-002: Unique table names
    let all_tables: Vec<&str> = actual
        .iter()
        .flat_map(|c| c.tables.iter().map(|t| t.as_str()))
        .collect();
    let unique_tables: BTreeSet<&str> = all_tables.iter().copied().collect();
    results.push(ConformanceTestResult {
        requirement_id: "BD1A1J-UNIQUE-002".to_string(),
        section: "uniqueness_constraints".to_string(),
        level: RequirementLevel::Must,
        description: "Table names MUST be unique across all persistence classes".to_string(),
        status: if all_tables.len() == unique_tables.len() {
            TestStatus::Pass
        } else {
            TestStatus::Fail
        },
        details: Some(format!(
            "total tables: {}, unique tables: {}",
            all_tables.len(),
            unique_tables.len()
        )),
    });

    results
}

/// BD1A1J-ADAPTER-* tests: Adapter behavior requirements

fn test_adapter_behavior() -> Vec<ConformanceTestResult> {
    let mut results = Vec::new();

    // BD1A1J-ADAPTER-001: Initialization event emission
    let adapter = FrankensqliteAdapter::new(AdapterConfig::default());
    results.push(ConformanceTestResult {
        requirement_id: "BD1A1J-ADAPTER-001".to_string(),
        section: "adapter_behavior".to_string(),
        level: RequirementLevel::Must,
        description: "Adapter MUST emit initialization event on creation".to_string(),
        status: if !adapter.events().is_empty() {
            TestStatus::Pass
        } else {
            TestStatus::Fail
        },
        details: Some(format!("event count: {}", adapter.events().len())),
    });

    // BD1A1J-ADAPTER-002: Gate behavior with no classes
    results.push(ConformanceTestResult {
        requirement_id: "BD1A1J-ADAPTER-002".to_string(),
        section: "adapter_behavior".to_string(),
        level: RequirementLevel::Must,
        description: "Adapter gate MUST fail when no classes are registered".to_string(),
        status: if !adapter.gate_pass() {
            TestStatus::Pass
        } else {
            TestStatus::Fail
        },
        details: Some("empty adapter gate should fail".to_string()),
    });

    // BD1A1J-ADAPTER-003: Gate behavior with all canonical classes
    let mut loaded_adapter = FrankensqliteAdapter::new(AdapterConfig::default());
    for class in canonical_classes() {
        loaded_adapter.register_class(class);
    }
    results.push(ConformanceTestResult {
        requirement_id: "BD1A1J-ADAPTER-003".to_string(),
        section: "adapter_behavior".to_string(),
        level: RequirementLevel::Must,
        description: "Adapter gate MUST pass when all canonical classes are registered".to_string(),
        status: if loaded_adapter.gate_pass() {
            TestStatus::Pass
        } else {
            TestStatus::Fail
        },
        details: Some(format!(
            "registered classes: {}",
            loaded_adapter.summary().total_classes
        )),
    });

    results
}

/// Helper functions

fn count_by_tier(classes: &[PersistenceClass]) -> BTreeMap<String, u32> {
    let mut counts = BTreeMap::new();
    for class in classes {
        let tier = match class.safety_tier {
            SafetyTier::Tier1 => "tier_1",
            SafetyTier::Tier2 => "tier_2",
            SafetyTier::Tier3 => "tier_3",
        };
        *counts.entry(tier.to_string()).or_insert(0) += 1;
    }
    counts
}

/// Generate conformance compliance report

pub fn generate_conformance_report(results: &[ConformanceTestResult]) -> String {
    let total = results.len();
    let passed = results
        .iter()
        .filter(|r| r.status == TestStatus::Pass)
        .count();
    let failed = results
        .iter()
        .filter(|r| r.status == TestStatus::Fail)
        .count();
    let xfailed = results
        .iter()
        .filter(|r| r.status == TestStatus::ExpectedFailure)
        .count();

    let mut by_section: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for result in results {
        let entry = by_section.entry(&result.section).or_insert((0, 0));
        entry.1 += 1; // total
        if result.status == TestStatus::Pass {
            entry.0 += 1; // passed
        }
    }

    let mut report = String::new();
    report.push_str("# BD-1A1J Frankensqlite Conformance Report\n\n");
    report.push_str(&format!(
        "**Overall**: {}/{} pass ({:.1}% compliance)\n\n",
        passed,
        total,
        (passed as f64 / total as f64) * 100.0
    ));

    report.push_str("## Coverage Matrix\n\n");
    report.push_str("| Section | MUST Tests | Passed | Score |\n");
    report.push_str("|---------|------------|--------| ------|\n");

    for (section, (passed, total)) in by_section {
        let score = (passed as f64 / total as f64) * 100.0;
        report.push_str(&format!(
            "| {} | {} | {} | {:.1}% |\n",
            section, total, passed, score
        ));
    }

    if failed > 0 {
        report.push_str("\n## Failed Requirements\n\n");
        for result in results.iter().filter(|r| r.status == TestStatus::Fail) {
            report.push_str(&format!(
                "- **{}**: {} ({})\n",
                result.requirement_id,
                result.description,
                result.details.as_deref().unwrap_or("no details")
            ));
        }
    }

    report
}

/// Main conformance test entry point

#[test]
fn bd1a1j_full_conformance() {
    let results = run_bd1a1j_conformance_suite();

    // Generate structured JSON output for CI
    for result in &results {
        eprintln!(
            "{{\"id\":\"{}\",\"status\":\"{:?}\",\"level\":\"{:?}\",\"section\":\"{}\"}}",
            result.requirement_id, result.status, result.level, result.section
        );
    }

    let failed_count = results
        .iter()
        .filter(|r| r.status == TestStatus::Fail)
        .count();
    let total_count = results.len();
    let compliance_score = (total_count - failed_count) as f64 / total_count as f64;

    // Generate report
    let report = generate_conformance_report(&results);
    eprintln!("\n{}", report);

    // Fail if any MUST requirements fail
    assert_eq!(
        failed_count,
        0,
        "{} out of {} conformance requirements failed (compliance: {:.1}%)",
        failed_count,
        total_count,
        compliance_score * 100.0
    );
}

// Re-export for adapter integration tests
pub use adapter_types::{AdapterConfig, FrankensqliteAdapter, canonical_classes};
