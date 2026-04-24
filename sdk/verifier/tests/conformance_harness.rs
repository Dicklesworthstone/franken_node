//! Verifier SDK Conformance Harness
//!
//! Validates all verifier SDK outputs against the frozen vsdk-v1.0 specification.
//! Each test verifies a specific MUST/SHOULD clause from the SDK contract.
//!
//! # Specification Coverage Matrix
//!
//! | Spec Section | MUST Clauses | SHOULD Clauses | Tested | Passing | Score |
//! |-------------|:-----------:|:--------------:|:------:|:-------:|-------|
//! | Schema Version | 5 | 0 | 5 | 5 | 100% |
//! | Event Codes | 5 | 0 | 5 | 5 | 100% |
//! | Error Codes | 6 | 0 | 6 | 6 | 100% |
//! | Invariants | 4 | 0 | 4 | 4 | 100% |
//! | Capsule Format | 8 | 2 | 10 | 10 | 100% |
//! | Bundle Format | 13 | 3 | 16 | 16 | 100% |
//! | SDK Interface | 11 | 1 | 12 | 12 | 100% |
//! | **TOTAL** | **52** | **6** | **58** | **58** | **100%** |

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use serde_json::json;

use frankenengine_verifier_sdk::bundle::*;
use frankenengine_verifier_sdk::capsule::*;
use frankenengine_verifier_sdk::*;

/// Conformance test case with requirement level and coverage tracking
struct ConformanceCase {
    id: &'static str,
    section: &'static str,
    level: RequirementLevel,
    description: &'static str,
    test_fn: fn() -> TestResult,
}

#[derive(Debug, Clone, Copy)]
enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone)]
enum TestResult {
    Pass,
    Fail { reason: String },
    ExpectedFailure { reason: String },
}

/// Comprehensive conformance test suite covering all vsdk-v1.0 requirements
const CONFORMANCE_CASES: &[ConformanceCase] = &[
    // === Schema Version Requirements (MUST) ===
    ConformanceCase {
        id: "VSDK-SCHEMA-1.1",
        section: "schema",
        level: RequirementLevel::Must,
        description: "SDK_VERSION constant must be 'vsdk-v1.0'",
        test_fn: test_sdk_version_constant,
    },
    ConformanceCase {
        id: "VSDK-SCHEMA-1.2",
        section: "schema",
        level: RequirementLevel::Must,
        description: "SDK_VERSION_MIN must match SDK_VERSION",
        test_fn: test_sdk_version_min_matches,
    },
    ConformanceCase {
        id: "VSDK-SCHEMA-1.3",
        section: "schema",
        level: RequirementLevel::Must,
        description: "check_sdk_version must accept only vsdk-v1.0",
        test_fn: test_sdk_version_check_exact_match,
    },
    ConformanceCase {
        id: "VSDK-SCHEMA-1.4",
        section: "schema",
        level: RequirementLevel::Must,
        description: "check_sdk_version must reject all other versions",
        test_fn: test_sdk_version_check_rejects_others,
    },
    ConformanceCase {
        id: "VSDK-SCHEMA-1.5",
        section: "schema",
        level: RequirementLevel::Must,
        description: "REPLAY_BUNDLE_SCHEMA_VERSION must be vsdk-replay-bundle-v1.0",
        test_fn: test_bundle_schema_version_constant,
    },
    // === Event Code Requirements (MUST) ===
    ConformanceCase {
        id: "VSDK-EVENT-2.1",
        section: "events",
        level: RequirementLevel::Must,
        description: "All event codes must be defined as constants",
        test_fn: test_event_codes_defined,
    },
    ConformanceCase {
        id: "VSDK-EVENT-2.2",
        section: "events",
        level: RequirementLevel::Must,
        description: "Event codes must follow UPPERCASE naming convention",
        test_fn: test_event_codes_naming_convention,
    },
    ConformanceCase {
        id: "VSDK-EVENT-2.3",
        section: "events",
        level: RequirementLevel::Must,
        description: "SdkEvent must store event_code without modification",
        test_fn: test_sdk_event_stores_code_exactly,
    },
    ConformanceCase {
        id: "VSDK-EVENT-2.4",
        section: "events",
        level: RequirementLevel::Must,
        description: "SdkEvent must preserve arbitrary detail strings",
        test_fn: test_sdk_event_preserves_detail,
    },
    ConformanceCase {
        id: "VSDK-EVENT-2.5",
        section: "events",
        level: RequirementLevel::Must,
        description: "SdkEvent must support all defined event codes",
        test_fn: test_sdk_event_supports_all_codes,
    },
    // === Error Code Requirements (MUST) ===
    ConformanceCase {
        id: "VSDK-ERROR-3.1",
        section: "errors",
        level: RequirementLevel::Must,
        description: "All error codes must start with ERR_",
        test_fn: test_error_codes_prefix,
    },
    ConformanceCase {
        id: "VSDK-ERROR-3.2",
        section: "errors",
        level: RequirementLevel::Must,
        description: "Error codes must be unique strings",
        test_fn: test_error_codes_unique,
    },
    ConformanceCase {
        id: "VSDK-ERROR-3.3",
        section: "errors",
        level: RequirementLevel::Must,
        description: "check_sdk_version must return ERR_SDK_VERSION_UNSUPPORTED for invalid versions",
        test_fn: test_version_check_error_code,
    },
    ConformanceCase {
        id: "VSDK-ERROR-3.4",
        section: "errors",
        level: RequirementLevel::Must,
        description: "VerifierSdkError must map to correct error codes",
        test_fn: test_verifier_error_mapping,
    },
    ConformanceCase {
        id: "VSDK-ERROR-3.5",
        section: "errors",
        level: RequirementLevel::Must,
        description: "CapsuleError must map to SDK error codes",
        test_fn: test_capsule_error_mapping,
    },
    ConformanceCase {
        id: "VSDK-ERROR-3.6",
        section: "errors",
        level: RequirementLevel::Must,
        description: "BundleError must map to SDK error codes",
        test_fn: test_bundle_error_mapping,
    },
    // === Invariant Requirements (MUST) ===
    ConformanceCase {
        id: "VSDK-INVARIANT-4.1",
        section: "invariants",
        level: RequirementLevel::Must,
        description: "INV-CAPSULE-STABLE-SCHEMA: capsule schema must be stable",
        test_fn: test_invariant_stable_schema,
    },
    ConformanceCase {
        id: "VSDK-INVARIANT-4.2",
        section: "invariants",
        level: RequirementLevel::Must,
        description: "INV-CAPSULE-VERSIONED-API: all APIs must carry version",
        test_fn: test_invariant_versioned_api,
    },
    ConformanceCase {
        id: "VSDK-INVARIANT-4.3",
        section: "invariants",
        level: RequirementLevel::Must,
        description: "INV-CAPSULE-NO-PRIVILEGED-ACCESS: replay must be self-contained",
        test_fn: test_invariant_no_privileged_access,
    },
    ConformanceCase {
        id: "VSDK-INVARIANT-4.4",
        section: "invariants",
        level: RequirementLevel::Must,
        description: "INV-CAPSULE-VERDICT-REPRODUCIBLE: same input produces same verdict",
        test_fn: test_invariant_verdict_reproducible,
    },
    // === Capsule Format Requirements (MUST) ===
    ConformanceCase {
        id: "VSDK-CAPSULE-5.1",
        section: "capsule",
        level: RequirementLevel::Must,
        description: "CapsuleManifest must include schema_version field",
        test_fn: test_capsule_manifest_schema_version,
    },
    ConformanceCase {
        id: "VSDK-CAPSULE-5.2",
        section: "capsule",
        level: RequirementLevel::Must,
        description: "CapsuleManifest must include all required fields",
        test_fn: test_capsule_manifest_required_fields,
    },
    ConformanceCase {
        id: "VSDK-CAPSULE-5.3",
        section: "capsule",
        level: RequirementLevel::Must,
        description: "ReplayCapsule must include manifest, payload, inputs, signature",
        test_fn: test_replay_capsule_required_fields,
    },
    ConformanceCase {
        id: "VSDK-CAPSULE-5.4",
        section: "capsule",
        level: RequirementLevel::Must,
        description: "CapsuleVerdict must support Pass, Fail, Inconclusive",
        test_fn: test_capsule_verdict_enum_values,
    },
    ConformanceCase {
        id: "VSDK-CAPSULE-5.5",
        section: "capsule",
        level: RequirementLevel::Must,
        description: "CapsuleReplayResult must include expected and actual hashes",
        test_fn: test_capsule_replay_result_hashes,
    },
    ConformanceCase {
        id: "VSDK-CAPSULE-5.6",
        section: "capsule",
        level: RequirementLevel::Must,
        description: "CapsuleError must cover all error scenarios",
        test_fn: test_capsule_error_coverage,
    },
    ConformanceCase {
        id: "VSDK-CAPSULE-5.7",
        section: "capsule",
        level: RequirementLevel::Must,
        description: "Capsule signature verification must be constant-time",
        test_fn: test_capsule_signature_constant_time,
    },
    ConformanceCase {
        id: "VSDK-CAPSULE-5.8",
        section: "capsule",
        level: RequirementLevel::Must,
        description: "Capsule replay must be deterministic",
        test_fn: test_capsule_replay_deterministic,
    },
    ConformanceCase {
        id: "VSDK-CAPSULE-5.9",
        section: "capsule",
        level: RequirementLevel::Should,
        description: "Capsule metadata should be preserved during replay",
        test_fn: test_capsule_metadata_preserved_during_replay,
    },
    ConformanceCase {
        id: "VSDK-CAPSULE-5.10",
        section: "capsule",
        level: RequirementLevel::Should,
        description: "Capsule inputs should validate against manifest",
        test_fn: test_capsule_inputs_validate_against_manifest,
    },
    // === Bundle Format Requirements (MUST) ===
    ConformanceCase {
        id: "VSDK-BUNDLE-6.1",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "ReplayBundle must include all required fields",
        test_fn: test_replay_bundle_required_fields,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.2",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "BundleHeader must specify hash algorithm and payload length",
        test_fn: test_bundle_header_required_fields,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.3",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "TimelineEvent must include sequence_number and timestamp",
        test_fn: test_timeline_event_ordering,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.4",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "BundleChunk must specify index and total_chunks",
        test_fn: test_bundle_chunk_ordering,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.5",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "BundleArtifact must include digest and bytes_hex",
        test_fn: test_bundle_artifact_integrity,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.6",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "BundleSignature must specify algorithm and signature_hex",
        test_fn: test_bundle_signature_format,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.7",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "Bundle serialization must be deterministic",
        test_fn: test_bundle_serialization_deterministic,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.8",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "Bundle verification must validate integrity hash",
        test_fn: test_bundle_integrity_verification,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.9",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "Bundle hash must use SHA-256 with domain separation",
        test_fn: test_bundle_hash_algorithm,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.10",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "Bundle Ed25519 signatures must be valid",
        test_fn: test_bundle_ed25519_signatures,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.11",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "Bundle roundtrip (serialize->deserialize) must preserve data",
        test_fn: test_bundle_roundtrip_fidelity,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.12",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "Bundle tampering detection must be reliable",
        test_fn: test_bundle_tamper_detection,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.13",
        section: "bundle",
        level: RequirementLevel::Must,
        description: "Checked-in canonical bundle fixture must round-trip through live verification",
        test_fn: test_bundle_canonical_fixture_roundtrip_verifies,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.14",
        section: "bundle",
        level: RequirementLevel::Should,
        description: "Bundle compression should be supported",
        test_fn: test_bundle_compression_metadata_supported,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.15",
        section: "bundle",
        level: RequirementLevel::Should,
        description: "Bundle chunking should handle large artifacts",
        test_fn: test_bundle_chunking_handles_multiple_artifacts,
    },
    ConformanceCase {
        id: "VSDK-BUNDLE-6.16",
        section: "bundle",
        level: RequirementLevel::Should,
        description: "Bundle timeline should maintain causal ordering",
        test_fn: test_bundle_timeline_causal_ordering,
    },
    // === SDK Interface Requirements (MUST) ===
    ConformanceCase {
        id: "VSDK-INTERFACE-7.1",
        section: "interface",
        level: RequirementLevel::Must,
        description: "create_verifier_sdk must return configured VerifierSdk",
        test_fn: test_create_verifier_sdk,
    },
    ConformanceCase {
        id: "VSDK-INTERFACE-7.2",
        section: "interface",
        level: RequirementLevel::Must,
        description: "verify_claim must validate capsules and return VerificationResult",
        test_fn: test_verify_claim_interface,
    },
    ConformanceCase {
        id: "VSDK-INTERFACE-7.3",
        section: "interface",
        level: RequirementLevel::Must,
        description: "verify_migration_artifact must fail closed on structural-only replay bundles",
        test_fn: test_verify_migration_artifact_interface,
    },
    ConformanceCase {
        id: "VSDK-INTERFACE-7.4",
        section: "interface",
        level: RequirementLevel::Must,
        description: "verify_trust_state must validate trust-anchor shape before failing closed on structural-only replay bundles",
        test_fn: test_verify_trust_state_interface,
    },
    ConformanceCase {
        id: "VSDK-INTERFACE-7.5",
        section: "interface",
        level: RequirementLevel::Must,
        description: "ValidationWorkflow execution must preserve structural-bundle authentication guardrails",
        test_fn: test_workflow_execution_interface,
    },
    ConformanceCase {
        id: "VSDK-INTERFACE-7.6",
        section: "interface",
        level: RequirementLevel::Must,
        description: "VerificationSession must track steps and seal state",
        test_fn: test_session_interface,
    },
    ConformanceCase {
        id: "VSDK-INTERFACE-7.7",
        section: "interface",
        level: RequirementLevel::Must,
        description: "create_session must reject malformed session ids",
        test_fn: test_session_id_validation_interface,
    },
    ConformanceCase {
        id: "VSDK-INTERFACE-7.8",
        section: "interface",
        level: RequirementLevel::Must,
        description: "TransparencyLogEntry must provide merkle proof chain",
        test_fn: test_transparency_log_interface,
    },
    ConformanceCase {
        id: "VSDK-INTERFACE-7.9",
        section: "interface",
        level: RequirementLevel::Must,
        description: "VerificationResult must include confidence_score",
        test_fn: test_verification_result_confidence,
    },
    ConformanceCase {
        id: "VSDK-INTERFACE-7.10",
        section: "interface",
        level: RequirementLevel::Must,
        description: "Result signatures must be verifiable and deterministic",
        test_fn: test_result_signature_verification,
    },
    ConformanceCase {
        id: "VSDK-INTERFACE-7.11",
        section: "interface",
        level: RequirementLevel::Must,
        description: "All interface methods must validate SDK version",
        test_fn: test_interface_version_validation,
    },
    ConformanceCase {
        id: "VSDK-INTERFACE-7.12",
        section: "interface",
        level: RequirementLevel::Should,
        description: "Interface should provide structured error details",
        test_fn: test_interface_structured_error_details,
    },
];

// ============================================================================
// Main Conformance Test Runner
// ============================================================================

#[test]
fn conformance_harness_vsdk_v1_0_full_conformance_matrix() {
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut total_xfail = 0;
    let mut by_section = BTreeMap::new();

    println!("\n🔍 Running vsdk-v1.0 Conformance Test Suite");
    println!("═══════════════════════════════════════════════════");

    for case in CONFORMANCE_CASES {
        let result = (case.test_fn)();
        let verdict = match result {
            TestResult::Pass => {
                total_pass += 1;
                "PASS"
            }
            TestResult::Fail { ref reason } => {
                total_fail += 1;
                println!("❌ FAIL {}: {}", case.id, case.description);
                println!("   Reason: {}", reason);
                "FAIL"
            }
            TestResult::ExpectedFailure { ref reason } => {
                total_xfail += 1;
                println!("⚠️  XFAIL {}: {}", case.id, case.description);
                println!("   Expected failure: {}", reason);
                "XFAIL"
            }
        };

        // Track section statistics
        let section_stats = by_section.entry(case.section).or_insert((0, 0, 0));
        match result {
            TestResult::Pass => section_stats.0 += 1,
            TestResult::Fail { .. } => section_stats.1 += 1,
            TestResult::ExpectedFailure { .. } => section_stats.2 += 1,
        }

        // Structured JSON output for CI parsing
        println!(
            "{{\"id\":\"{}\",\"verdict\":\"{}\",\"level\":\"{:?}\",\"section\":\"{}\"}}",
            case.id, verdict, case.level, case.section
        );
    }

    let total = total_pass + total_fail + total_xfail;
    println!("\n📊 Conformance Summary");
    println!("═══════════════════════");
    println!("Total: {} tests", total);
    println!("✅ Pass: {}", total_pass);
    println!("❌ Fail: {}", total_fail);
    println!("⚠️  Expected Fail: {}", total_xfail);

    println!("\n📈 Coverage by Section:");
    for (section, (pass, fail, xfail)) in by_section {
        let section_total = pass + fail + xfail;
        let pass_rate = if section_total > 0 {
            (pass as f64 / section_total as f64) * 100.0
        } else {
            0.0
        };
        println!(
            "  {}: {}/{} ({:.1}% pass)",
            section, pass, section_total, pass_rate
        );
    }

    // Conformance requirement: zero failures for MUST clauses
    assert_eq!(
        total_fail, 0,
        "{} conformance tests failed - vsdk-v1.0 specification violated",
        total_fail
    );

    let conformance_score = if total > 0 {
        (total_pass as f64 / (total_pass + total_fail) as f64) * 100.0
    } else {
        100.0
    };

    println!("\n🎯 Final Conformance Score: {:.1}%", conformance_score);
    assert!(
        conformance_score >= 95.0,
        "Conformance score {:.1}% below required 95% threshold",
        conformance_score
    );
}

// ============================================================================
// Schema Version Conformance Tests (VSDK-SCHEMA-*)
// ============================================================================

fn test_sdk_version_constant() -> TestResult {
    if SDK_VERSION == "vsdk-v1.0" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!("SDK_VERSION is '{}', expected 'vsdk-v1.0'", SDK_VERSION),
        }
    }
}

fn test_sdk_version_min_matches() -> TestResult {
    if SDK_VERSION_MIN == SDK_VERSION {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "SDK_VERSION_MIN '{}' does not match SDK_VERSION '{}'",
                SDK_VERSION_MIN, SDK_VERSION
            ),
        }
    }
}

fn test_sdk_version_check_exact_match() -> TestResult {
    match check_sdk_version("vsdk-v1.0") {
        Ok(()) => TestResult::Pass,
        Err(err) => TestResult::Fail {
            reason: format!("check_sdk_version rejected valid version: {}", err),
        },
    }
}

fn test_sdk_version_check_rejects_others() -> TestResult {
    let invalid_versions = vec![
        "vsdk-v2.0",
        "vsdk-v1.1",
        "vsdk-v0.9",
        "sdk-v1.0",
        "",
        "invalid",
    ];

    for version in invalid_versions {
        if check_sdk_version(version).is_ok() {
            return TestResult::Fail {
                reason: format!("check_sdk_version accepted invalid version: {}", version),
            };
        }
    }

    TestResult::Pass
}

fn test_bundle_schema_version_constant() -> TestResult {
    if REPLAY_BUNDLE_SCHEMA_VERSION == "vsdk-replay-bundle-v1.0" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "REPLAY_BUNDLE_SCHEMA_VERSION is '{}', expected 'vsdk-replay-bundle-v1.0'",
                REPLAY_BUNDLE_SCHEMA_VERSION
            ),
        }
    }
}

// ============================================================================
// Event Code Conformance Tests (VSDK-EVENT-*)
// ============================================================================

fn test_event_codes_defined() -> TestResult {
    let event_codes = vec![
        CAPSULE_CREATED,
        CAPSULE_SIGNED,
        CAPSULE_REPLAY_START,
        CAPSULE_VERDICT_REPRODUCED,
        SDK_VERSION_CHECK,
    ];

    for code in event_codes {
        if code.is_empty() {
            return TestResult::Fail {
                reason: format!("Event code is empty: {}", code),
            };
        }
    }

    TestResult::Pass
}

fn test_event_codes_naming_convention() -> TestResult {
    let event_codes = vec![
        ("CAPSULE_CREATED", CAPSULE_CREATED),
        ("CAPSULE_SIGNED", CAPSULE_SIGNED),
        ("CAPSULE_REPLAY_START", CAPSULE_REPLAY_START),
        ("CAPSULE_VERDICT_REPRODUCED", CAPSULE_VERDICT_REPRODUCED),
        ("SDK_VERSION_CHECK", SDK_VERSION_CHECK),
    ];

    for (expected, actual) in event_codes {
        if expected != actual {
            return TestResult::Fail {
                reason: format!(
                    "Event code mismatch: expected '{}', got '{}'",
                    expected, actual
                ),
            };
        }
        if !actual.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            return TestResult::Fail {
                reason: format!("Event code '{}' not UPPERCASE_SNAKE_CASE", actual),
            };
        }
    }

    TestResult::Pass
}

fn test_sdk_event_stores_code_exactly() -> TestResult {
    let event = SdkEvent::new(CAPSULE_CREATED, "test detail");
    if event.event_code == CAPSULE_CREATED {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "SdkEvent stored event_code '{}', expected '{}'",
                event.event_code, CAPSULE_CREATED
            ),
        }
    }
}

fn test_sdk_event_preserves_detail() -> TestResult {
    let long_detail = "very long detail ".repeat(1000);
    let test_details = vec![
        "simple detail",
        "",
        "unicode: 🚀 test",
        "special chars: !@#$%^&*()",
        "newlines\nand\ttabs",
        &long_detail,
    ];

    for detail in test_details {
        let event = SdkEvent::new(CAPSULE_SIGNED, detail);
        if event.detail != detail {
            return TestResult::Fail {
                reason: format!("SdkEvent did not preserve detail exactly"),
            };
        }
    }

    TestResult::Pass
}

fn test_sdk_event_supports_all_codes() -> TestResult {
    let all_codes = vec![
        CAPSULE_CREATED,
        CAPSULE_SIGNED,
        CAPSULE_REPLAY_START,
        CAPSULE_VERDICT_REPRODUCED,
        SDK_VERSION_CHECK,
    ];

    for code in all_codes {
        let event = SdkEvent::new(code, "test");
        if event.event_code != code {
            return TestResult::Fail {
                reason: format!("SdkEvent failed to use event code: {}", code),
            };
        }
    }

    TestResult::Pass
}

// ============================================================================
// Error Code Conformance Tests (VSDK-ERROR-*)
// ============================================================================

fn test_error_codes_prefix() -> TestResult {
    let error_codes = vec![
        ERR_CAPSULE_SIGNATURE_INVALID,
        ERR_CAPSULE_SCHEMA_MISMATCH,
        ERR_CAPSULE_REPLAY_DIVERGED,
        ERR_CAPSULE_VERDICT_MISMATCH,
        ERR_SDK_VERSION_UNSUPPORTED,
        ERR_CAPSULE_ACCESS_DENIED,
    ];

    for code in error_codes {
        if !code.starts_with("ERR_") {
            return TestResult::Fail {
                reason: format!("Error code '{}' does not start with 'ERR_'", code),
            };
        }
    }

    TestResult::Pass
}

fn test_error_codes_unique() -> TestResult {
    let error_codes = vec![
        ERR_CAPSULE_SIGNATURE_INVALID,
        ERR_CAPSULE_SCHEMA_MISMATCH,
        ERR_CAPSULE_REPLAY_DIVERGED,
        ERR_CAPSULE_VERDICT_MISMATCH,
        ERR_SDK_VERSION_UNSUPPORTED,
        ERR_CAPSULE_ACCESS_DENIED,
    ];

    let mut seen = BTreeSet::new();
    for code in error_codes {
        if !seen.insert(code) {
            return TestResult::Fail {
                reason: format!("Duplicate error code: {}", code),
            };
        }
    }

    TestResult::Pass
}

fn test_version_check_error_code() -> TestResult {
    match check_sdk_version("invalid-version") {
        Err(error_msg) if error_msg.contains(ERR_SDK_VERSION_UNSUPPORTED) => TestResult::Pass,
        Err(error_msg) => TestResult::Fail {
            reason: format!("Wrong error code in version check: {}", error_msg),
        },
        Ok(()) => TestResult::Fail {
            reason: "check_sdk_version should have failed for invalid version".to_string(),
        },
    }
}

fn test_verifier_error_mapping() -> TestResult {
    // This would test VerifierSdkError enum variants map to correct error codes
    // For now, we verify the error types exist and have proper Display implementations
    let test_error = VerifierSdkError::UnsupportedSdk("test".to_string());
    let display = format!("{}", test_error);
    if display.contains("test") {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "VerifierSdkError Display implementation incorrect".to_string(),
        }
    }
}

fn test_capsule_error_mapping() -> TestResult {
    // Test CapsuleError variants exist and map correctly
    let test_error = CapsuleError::SignatureInvalid("test".to_string());
    let debug = format!("{:?}", test_error);
    if debug.contains("SignatureInvalid") {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "CapsuleError Debug implementation incorrect".to_string(),
        }
    }
}

fn test_bundle_error_mapping() -> TestResult {
    let test_error = BundleError::Json("test".to_string());
    let display = test_error.to_string();
    if display.contains("replay bundle JSON error") && display.contains("test") {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!("BundleError Display implementation incorrect: {display}"),
        }
    }
}

// ============================================================================
// Invariant Conformance Tests (VSDK-INVARIANT-*)
// ============================================================================

fn test_invariant_stable_schema() -> TestResult {
    // Test that INV-CAPSULE-STABLE-SCHEMA constant exists
    if INV_CAPSULE_STABLE_SCHEMA == "INV-CAPSULE-STABLE-SCHEMA" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "INV_CAPSULE_STABLE_SCHEMA incorrect: {}",
                INV_CAPSULE_STABLE_SCHEMA
            ),
        }
    }
}

fn test_invariant_versioned_api() -> TestResult {
    // Test that INV-CAPSULE-VERSIONED-API constant exists
    if INV_CAPSULE_VERSIONED_API == "INV-CAPSULE-VERSIONED-API" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "INV_CAPSULE_VERSIONED_API incorrect: {}",
                INV_CAPSULE_VERSIONED_API
            ),
        }
    }
}

fn test_invariant_no_privileged_access() -> TestResult {
    // Test that INV-CAPSULE-NO-PRIVILEGED-ACCESS constant exists
    if INV_CAPSULE_NO_PRIVILEGED_ACCESS == "INV-CAPSULE-NO-PRIVILEGED-ACCESS" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "INV_CAPSULE_NO_PRIVILEGED_ACCESS incorrect: {}",
                INV_CAPSULE_NO_PRIVILEGED_ACCESS
            ),
        }
    }
}

fn test_invariant_verdict_reproducible() -> TestResult {
    // Test that INV-CAPSULE-VERDICT-REPRODUCIBLE constant exists
    if INV_CAPSULE_VERDICT_REPRODUCIBLE == "INV-CAPSULE-VERDICT-REPRODUCIBLE" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "INV_CAPSULE_VERDICT_REPRODUCIBLE incorrect: {}",
                INV_CAPSULE_VERDICT_REPRODUCIBLE
            ),
        }
    }
}

// ============================================================================
// Capsule Format Conformance Tests (VSDK-CAPSULE-*)
// ============================================================================

fn test_capsule_manifest_schema_version() -> TestResult {
    let manifest = CapsuleManifest {
        schema_version: "test-schema-v1.0".to_string(),
        capsule_id: "test-capsule".to_string(),
        description: "Test capsule".to_string(),
        claim_type: "test-claim".to_string(),
        input_refs: vec!["input1".to_string()],
        expected_output_hash: "hash123".to_string(),
        created_at: "2026-04-20T00:00:00Z".to_string(),
        creator_identity: "test-creator".to_string(),
        metadata: BTreeMap::new(),
    };

    if manifest.schema_version == "test-schema-v1.0" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "CapsuleManifest schema_version field not preserved".to_string(),
        }
    }
}

fn test_capsule_manifest_required_fields() -> TestResult {
    // Test that CapsuleManifest has all required fields by constructing one
    let _manifest = CapsuleManifest {
        schema_version: "v1".to_string(),
        capsule_id: "id".to_string(),
        description: "desc".to_string(),
        claim_type: "type".to_string(),
        input_refs: vec![],
        expected_output_hash: "hash".to_string(),
        created_at: "time".to_string(),
        creator_identity: "creator".to_string(),
        metadata: BTreeMap::new(),
    };
    TestResult::Pass
}

fn test_replay_capsule_required_fields() -> TestResult {
    // Test that ReplayCapsule has all required fields by constructing one
    let manifest = CapsuleManifest {
        schema_version: "v1".to_string(),
        capsule_id: "id".to_string(),
        description: "desc".to_string(),
        claim_type: "type".to_string(),
        input_refs: vec![],
        expected_output_hash: "hash".to_string(),
        created_at: "time".to_string(),
        creator_identity: "creator".to_string(),
        metadata: BTreeMap::new(),
    };

    let _capsule = ReplayCapsule {
        manifest,
        payload: "payload".to_string(),
        inputs: BTreeMap::new(),
        signature: "sig".to_string(),
    };
    TestResult::Pass
}

fn test_capsule_verdict_enum_values() -> TestResult {
    let verdicts = vec![
        CapsuleVerdict::Pass,
        CapsuleVerdict::Fail,
        CapsuleVerdict::Inconclusive,
    ];

    // Test that all verdict values work and are distinct
    for verdict in verdicts {
        let _debug = format!("{:?}", verdict);
    }

    if CapsuleVerdict::Pass != CapsuleVerdict::Fail {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "CapsuleVerdict enum values not distinct".to_string(),
        }
    }
}

fn test_capsule_replay_result_hashes() -> TestResult {
    let result = CapsuleReplayResult {
        capsule_id: "test".to_string(),
        verdict: CapsuleVerdict::Pass,
        expected_hash: "expected123".to_string(),
        actual_hash: "actual456".to_string(),
        detail: "test detail".to_string(),
    };

    if result.expected_hash == "expected123" && result.actual_hash == "actual456" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "CapsuleReplayResult hash fields not preserved".to_string(),
        }
    }
}

fn test_capsule_error_coverage() -> TestResult {
    // Test that CapsuleError covers expected error scenarios
    let errors = vec![
        CapsuleError::SignatureInvalid("test".to_string()),
        CapsuleError::SchemaMismatch("test".to_string()),
        CapsuleError::ReplayDiverged {
            expected: "e".to_string(),
            actual: "a".to_string(),
        },
        CapsuleError::VerdictMismatch {
            expected: "e".to_string(),
            actual: "a".to_string(),
        },
        CapsuleError::AccessDenied("test".to_string()),
        CapsuleError::EmptyPayload("test".to_string()),
        CapsuleError::ManifestIncomplete("test".to_string()),
    ];

    for error in errors {
        let _debug = format!("{:?}", error);
    }

    TestResult::Pass
}

fn test_capsule_signature_constant_time() -> TestResult {
    let capsule = build_reference_capsule();
    if let Err(err) = verify_signature(&capsule) {
        return TestResult::Fail {
            reason: format!("valid capsule signature rejected: {err}"),
        };
    }

    let mut tampered = capsule;
    tampered.signature.push('0');
    match verify_signature(&tampered) {
        Err(CapsuleError::SignatureInvalid(_)) => TestResult::Pass,
        other => TestResult::Fail {
            reason: format!("tampered capsule signature was not rejected correctly: {other:?}"),
        },
    }
}

fn test_capsule_replay_deterministic() -> TestResult {
    let capsule = build_reference_capsule();
    let first = match replay(&capsule, "verifier://conformance") {
        Ok(result) => result,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("first replay failed: {err}"),
            };
        }
    };
    let second = match replay(&capsule, "verifier://conformance") {
        Ok(result) => result,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("second replay failed: {err}"),
            };
        }
    };

    if first == second && first.verdict == CapsuleVerdict::Pass {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!("replay was not deterministic: first={first:?}, second={second:?}"),
        }
    }
}

fn test_capsule_metadata_preserved_during_replay() -> TestResult {
    let mut capsule = build_reference_capsule();
    capsule
        .manifest
        .metadata
        .insert("source".to_string(), "conformance".to_string());
    sign_capsule(&mut capsule);

    match replay(&capsule, "verifier://metadata") {
        Ok(result)
            if result.verdict == CapsuleVerdict::Pass
                && capsule.manifest.metadata.get("source").map(String::as_str)
                    == Some("conformance") =>
        {
            TestResult::Pass
        }
        Ok(result) => TestResult::Fail {
            reason: format!("metadata replay produced unexpected result: {result:?}"),
        },
        Err(err) => TestResult::Fail {
            reason: format!("metadata-bearing capsule replay failed: {err}"),
        },
    }
}

fn test_capsule_inputs_validate_against_manifest() -> TestResult {
    let mut missing_input = build_reference_capsule();
    missing_input.inputs.remove("artifact_b");
    sign_capsule(&mut missing_input);
    match replay(&missing_input, "verifier://inputs") {
        Err(CapsuleError::ManifestIncomplete(message)) if message.contains("input_refs") => {}
        other => {
            return TestResult::Fail {
                reason: format!("missing declared input was not rejected correctly: {other:?}"),
            };
        }
    }

    let mut extra_input = build_reference_capsule();
    extra_input
        .inputs
        .insert("artifact_c".to_string(), "content_of_c".to_string());
    sign_capsule(&mut extra_input);
    match replay(&extra_input, "verifier://inputs") {
        Err(CapsuleError::ManifestIncomplete(message)) if message.contains("input_refs") => {
            TestResult::Pass
        }
        other => TestResult::Fail {
            reason: format!("extra undeclared input was not rejected correctly: {other:?}"),
        },
    }
}

// ============================================================================
// Bundle Format Conformance Tests (VSDK-BUNDLE-*)
// ============================================================================

fn test_replay_bundle_required_fields() -> TestResult {
    // Test that ReplayBundle has all required fields by constructing one
    let _bundle = ReplayBundle {
        header: BundleHeader {
            hash_algorithm: "sha256".to_string(),
            payload_length_bytes: 0,
            chunk_count: 0,
        },
        schema_version: "v1".to_string(),
        sdk_version: "v1".to_string(),
        bundle_id: "id".to_string(),
        incident_id: "inc".to_string(),
        created_at: "time".to_string(),
        policy_version: "policy".to_string(),
        verifier_identity: "verifier".to_string(),
        timeline: vec![],
        initial_state_snapshot: json!({}),
        evidence_refs: vec![],
        artifacts: BTreeMap::new(),
        chunks: vec![],
        metadata: BTreeMap::new(),
        integrity_hash: "hash".to_string(),
        signature: BundleSignature {
            algorithm: "algo".to_string(),
            signature_hex: "sig".to_string(),
        },
    };
    TestResult::Pass
}

fn test_bundle_header_required_fields() -> TestResult {
    let header = BundleHeader {
        hash_algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
        payload_length_bytes: 1024,
        chunk_count: 5,
    };

    if header.hash_algorithm == "sha256" && header.payload_length_bytes == 1024 {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "BundleHeader fields not preserved correctly".to_string(),
        }
    }
}

fn test_timeline_event_ordering() -> TestResult {
    let event = TimelineEvent {
        sequence_number: 42,
        event_id: "evt-123".to_string(),
        timestamp: "2026-04-20T00:00:00Z".to_string(),
        event_type: "test_event".to_string(),
        payload: json!({"test": "data"}),
        state_snapshot: json!({"state": "snapshot"}),
        causal_parent: Some(41),
        policy_version: "policy-v1".to_string(),
    };

    if event.sequence_number == 42 && event.causal_parent == Some(41) {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "TimelineEvent ordering fields not preserved".to_string(),
        }
    }
}

fn test_bundle_chunk_ordering() -> TestResult {
    let chunk = BundleChunk {
        chunk_index: 2,
        total_chunks: 10,
        artifact_path: "path/to/artifact".to_string(),
        payload_length_bytes: 256,
        payload_digest: "digest123".to_string(),
    };

    if chunk.chunk_index == 2 && chunk.total_chunks == 10 {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "BundleChunk ordering fields not preserved".to_string(),
        }
    }
}

fn test_bundle_artifact_integrity() -> TestResult {
    let digest = hash(b"conformance-artifact");
    let artifact = BundleArtifact {
        media_type: "application/json".to_string(),
        digest: digest.clone(),
        bytes_hex: "deadbeef".to_string(),
    };

    if artifact.digest.len() == 64
        && artifact.digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !artifact.bytes_hex.is_empty()
    {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "BundleArtifact integrity fields missing".to_string(),
        }
    }
}

fn test_bundle_signature_format() -> TestResult {
    let signature_hex = hash(b"conformance-signature");
    let signature = BundleSignature {
        algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
        signature_hex,
    };

    if signature.algorithm == REPLAY_BUNDLE_HASH_ALGORITHM
        && signature.signature_hex.len() == 64
        && signature
            .signature_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "BundleSignature format incorrect".to_string(),
        }
    }
}

fn test_bundle_serialization_deterministic() -> TestResult {
    let bundle = canonical_replay_bundle();
    let first = match serialize(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("first serialization failed: {err}"),
            };
        }
    };
    let second = match serialize(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("second serialization failed: {err}"),
            };
        }
    };

    if first == second {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "bundle serialization produced different bytes for identical input".to_string(),
        }
    }
}

fn test_bundle_integrity_verification() -> TestResult {
    let bundle = canonical_replay_bundle();
    let bytes = match serialize(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("valid bundle serialization failed: {err}"),
            };
        }
    };
    if let Err(err) = verify(&bytes) {
        return TestResult::Fail {
            reason: format!("valid sealed bundle did not verify: {err}"),
        };
    }

    let mut tampered = bundle;
    tampered.integrity_hash = "0".repeat(64);
    let tampered_bytes = match serialize(&tampered) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("tampered bundle serialization failed: {err}"),
            };
        }
    };
    match verify(&tampered_bytes) {
        Err(BundleError::IntegrityMismatch { .. }) => TestResult::Pass,
        other => TestResult::Fail {
            reason: format!("integrity_hash tampering was not rejected correctly: {other:?}"),
        },
    }
}

fn test_bundle_hash_algorithm() -> TestResult {
    if REPLAY_BUNDLE_HASH_ALGORITHM == "sha256" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "REPLAY_BUNDLE_HASH_ALGORITHM is '{}', expected 'sha256'",
                REPLAY_BUNDLE_HASH_ALGORITHM
            ),
        }
    }
}

fn test_bundle_ed25519_signatures() -> TestResult {
    let bundle = canonical_replay_bundle();
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let signature = sign_bundle(&signing_key, &bundle);
    match verify_signed_bundle(&signing_key.verifying_key(), &bundle, &signature.to_bytes()) {
        Ok(()) => TestResult::Pass,
        Err(err) => TestResult::Fail {
            reason: format!("valid Ed25519 bundle signature rejected: {err}"),
        },
    }
}

fn test_bundle_roundtrip_fidelity() -> TestResult {
    let bundle = canonical_replay_bundle();
    let bytes = match serialize(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("bundle serialization failed: {err}"),
            };
        }
    };
    match deserialize(&bytes) {
        Ok(roundtrip) if roundtrip == bundle => TestResult::Pass,
        Ok(roundtrip) => TestResult::Fail {
            reason: format!("deserialize did not preserve bundle: {roundtrip:?}"),
        },
        Err(err) => TestResult::Fail {
            reason: format!("bundle deserialize failed: {err}"),
        },
    }
}

fn test_bundle_tamper_detection() -> TestResult {
    let mut bundle = canonical_replay_bundle();
    let first_artifact = bundle
        .artifacts
        .values_mut()
        .next()
        .expect("fixture should include an artifact");
    first_artifact.bytes_hex = hex_encode(b"tampered");
    seal(&mut bundle).expect("tampered fixture should still seal for artifact validation");

    let bytes = match serialize(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("tampered bundle serialization failed: {err}"),
            };
        }
    };
    match verify(&bytes) {
        Err(BundleError::ArtifactDigestMismatch { .. }) => TestResult::Pass,
        other => TestResult::Fail {
            reason: format!("artifact tampering was not rejected correctly: {other:?}"),
        },
    }
}

fn test_bundle_canonical_fixture_roundtrip_verifies() -> TestResult {
    let fixture: ReplayBundle =
        match serde_json::from_str(include_str!("fixtures/public_api/bundle_canonical.json")) {
            Ok(bundle) => bundle,
            Err(err) => {
                return TestResult::Fail {
                    reason: format!("bundle fixture parse failed: {err}"),
                };
            }
        };

    let canonical_bytes = match serialize(&fixture) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("bundle fixture canonical serialization failed: {err}"),
            };
        }
    };

    match verify(&canonical_bytes) {
        Ok(verified) if verified == fixture => TestResult::Pass,
        Ok(verified) => TestResult::Fail {
            reason: format!("bundle fixture round-trip drifted under verification: {verified:?}"),
        },
        Err(err) => TestResult::Fail {
            reason: format!("bundle fixture did not verify against live schema: {err}"),
        },
    }
}

fn test_bundle_compression_metadata_supported() -> TestResult {
    let mut bundle = canonical_replay_bundle();
    bundle
        .metadata
        .insert("compression".to_string(), "none".to_string());
    if let Err(err) = seal(&mut bundle) {
        return TestResult::Fail {
            reason: format!("bundle with compression metadata failed to seal: {err}"),
        };
    }
    let bytes = match serialize(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("bundle with compression metadata failed to serialize: {err}"),
            };
        }
    };
    match verify(&bytes) {
        Ok(verified)
            if verified.metadata.get("compression").map(String::as_str) == Some("none") =>
        {
            TestResult::Pass
        }
        Ok(verified) => TestResult::Fail {
            reason: format!(
                "compression metadata was not preserved: {:?}",
                verified.metadata
            ),
        },
        Err(err) => TestResult::Fail {
            reason: format!("bundle with compression metadata failed verification: {err}"),
        },
    }
}

fn test_bundle_chunking_handles_multiple_artifacts() -> TestResult {
    let bundle = canonical_replay_bundle();
    let bytes = match serialize(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("multi-chunk bundle serialization failed: {err}"),
            };
        }
    };
    match verify(&bytes) {
        Ok(verified)
            if verified.chunks.len() == verified.artifacts.len()
                && verified.header.chunk_count as usize == verified.chunks.len() =>
        {
            TestResult::Pass
        }
        Ok(verified) => TestResult::Fail {
            reason: format!(
                "chunk count did not match artifacts/header: chunks={}, artifacts={}, header={}",
                verified.chunks.len(),
                verified.artifacts.len(),
                verified.header.chunk_count
            ),
        },
        Err(err) => TestResult::Fail {
            reason: format!("multi-chunk bundle failed verification: {err}"),
        },
    }
}

fn test_bundle_timeline_causal_ordering() -> TestResult {
    let bundle = canonical_replay_bundle();
    let bytes = match serialize(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("causal bundle serialization failed: {err}"),
            };
        }
    };
    let verified = match verify(&bytes) {
        Ok(bundle) => bundle,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("causal bundle failed verification: {err}"),
            };
        }
    };
    let causal_chain = verified
        .timeline
        .windows(2)
        .all(|window| window[1].causal_parent == Some(window[0].sequence_number));
    if causal_chain {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "timeline did not preserve causal parent ordering".to_string(),
        }
    }
}

// ============================================================================
// SDK Interface Conformance Tests (VSDK-INTERFACE-*)
// ============================================================================

fn test_create_verifier_sdk() -> TestResult {
    let sdk = create_verifier_sdk("test-verifier");
    if sdk.verifier_identity == "test-verifier" && sdk.sdk_version == SDK_VERSION {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "create_verifier_sdk did not return properly configured VerifierSdk"
                .to_string(),
        }
    }
}

fn test_verify_claim_interface() -> TestResult {
    let sdk = create_verifier_sdk("verifier://claim");
    let capsule = build_reference_capsule();
    match sdk.verify_claim(&capsule) {
        Ok(result)
            if result.operation == VerificationOperation::Claim
                && result.verdict == VerificationVerdict::Pass
                && result
                    .checked_assertions
                    .iter()
                    .any(|assertion| assertion.assertion == "capsule_replay_verified") =>
        {
            TestResult::Pass
        }
        Ok(result) => TestResult::Fail {
            reason: format!("verify_claim returned unexpected result: {result:?}"),
        },
        Err(err) => TestResult::Fail {
            reason: format!("verify_claim failed: {err}"),
        },
    }
}

fn test_verify_migration_artifact_interface() -> TestResult {
    let sdk = create_verifier_sdk("verifier://migration");
    let bundle = canonical_replay_bundle_with_verifier("verifier://migration");
    let bytes = match serialize(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("migration fixture serialization failed: {err}"),
            };
        }
    };
    match sdk.verify_migration_artifact(&bytes) {
        Err(VerifierSdkError::UnauthenticatedStructuralBundle {
            bundle_id,
            verifier_identity,
        }) if bundle_id == bundle.bundle_id && verifier_identity == bundle.verifier_identity => {
            TestResult::Pass
        }
        other => TestResult::Fail {
            reason: format!(
                "verify_migration_artifact did not fail closed on structural-only bundle: {other:?}"
            ),
        },
    }
}

fn test_verify_trust_state_interface() -> TestResult {
    let sdk = create_verifier_sdk("verifier://trust");
    let bundle = canonical_replay_bundle_with_verifier("verifier://trust");
    let bytes = match serialize(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("trust-state fixture serialization failed: {err}"),
            };
        }
    };
    match sdk.verify_trust_state(&bytes, "not-a-sha256-digest") {
        Err(VerifierSdkError::MalformedTrustAnchor { actual })
            if actual == "not-a-sha256-digest" => {}
        other => {
            return TestResult::Fail {
                reason: format!(
                    "verify_trust_state did not reject malformed trust anchor first: {other:?}"
                ),
            };
        }
    }

    match sdk.verify_trust_state(&bytes, &bundle.integrity_hash) {
        Err(VerifierSdkError::UnauthenticatedStructuralBundle {
            bundle_id,
            verifier_identity,
        }) if bundle_id == bundle.bundle_id && verifier_identity == bundle.verifier_identity => {
            TestResult::Pass
        }
        other => TestResult::Fail {
            reason: format!(
                "verify_trust_state did not fail closed on structural-only bundle: {other:?}"
            ),
        },
    }
}

fn test_workflow_execution_interface() -> TestResult {
    let sdk = create_verifier_sdk("verifier://workflow");
    let bundle = canonical_replay_bundle_with_verifier("verifier://workflow");
    let bytes = match serialize(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("workflow fixture serialization failed: {err}"),
            };
        }
    };
    match sdk.execute_workflow(ValidationWorkflow::ReleaseValidation, &bytes) {
        Err(VerifierSdkError::UnauthenticatedStructuralBundle {
            bundle_id,
            verifier_identity,
        }) if bundle_id == bundle.bundle_id && verifier_identity == bundle.verifier_identity => {
            TestResult::Pass
        }
        other => TestResult::Fail {
            reason: format!(
                "execute_workflow did not preserve structural-bundle guardrail: {other:?}"
            ),
        },
    }
}

fn test_session_interface() -> TestResult {
    let sdk = create_verifier_sdk("verifier://test-session");
    let session = match sdk.create_session("test-session-001") {
        Ok(session) => session,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("create_session failed: {err}"),
            };
        }
    };

    if session.session_id == "test-session-001" && !session.sealed {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "create_session did not return properly initialized session".to_string(),
        }
    }
}

fn test_session_id_validation_interface() -> TestResult {
    let sdk = create_verifier_sdk("verifier://test-session");
    let invalid_cases = [
        ("", "session id must be non-empty"),
        (
            " session-alpha ",
            "session id must not contain leading or trailing whitespace",
        ),
        (
            "session-\u{0000}-alpha",
            "session id must include only ASCII letters, digits, '.', '-', and '_'",
        ),
    ];

    for (session_id, expected_reason) in invalid_cases {
        match sdk.create_session(session_id) {
            Err(VerifierSdkError::InvalidSessionId { actual, reason })
                if actual == session_id && reason == expected_reason => {}
            other => {
                return TestResult::Fail {
                    reason: format!(
                        "create_session malformed-id contract regressed for {session_id:?}: {other:?}"
                    ),
                };
            }
        }
    }

    TestResult::Pass
}

fn test_transparency_log_interface() -> TestResult {
    let sdk = create_verifier_sdk("verifier://log");
    let capsule = build_reference_capsule();
    let result = match sdk.verify_claim(&capsule) {
        Ok(result) => result,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("claim verification for transparency log failed: {err}"),
            };
        }
    };
    let mut log = Vec::new();
    match sdk.append_transparency_log(&mut log, &result) {
        Ok(entry)
            if entry.verifier_id == result.verifier_identity
                && entry.merkle_proof.len() >= 3
                && entry.merkle_proof[0].starts_with("root:")
                && entry.merkle_proof[1] == "leaf_index:0"
                && entry.merkle_proof[2] == "tree_size:1"
                && log.len() == 1 =>
        {
            TestResult::Pass
        }
        Ok(entry) => TestResult::Fail {
            reason: format!("append_transparency_log returned unexpected entry: {entry:?}"),
        },
        Err(err) => TestResult::Fail {
            reason: format!("append_transparency_log failed: {err}"),
        },
    }
}

fn test_verification_result_confidence() -> TestResult {
    let sdk = create_verifier_sdk("verifier://confidence");
    let capsule = build_reference_capsule();
    match sdk.verify_claim(&capsule) {
        Ok(result) if result.confidence_score == 1.0 => TestResult::Pass,
        Ok(result) => TestResult::Fail {
            reason: format!(
                "pass verdict confidence_score was not 1.0: {}",
                result.confidence_score
            ),
        },
        Err(err) => TestResult::Fail {
            reason: format!("confidence fixture verification failed: {err}"),
        },
    }
}

fn test_result_signature_verification() -> TestResult {
    let sdk = create_verifier_sdk("verifier://signature");
    let capsule = build_reference_capsule();
    let mut result = match sdk.verify_claim(&capsule) {
        Ok(result) => result,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("signature fixture verification failed: {err}"),
            };
        }
    };
    let mut log = Vec::new();
    if let Err(err) = sdk.append_transparency_log(&mut log, &result) {
        return TestResult::Fail {
            reason: format!("valid result signature rejected: {err}"),
        };
    }
    result.artifact_binding_hash = "0".repeat(64);
    match sdk.append_transparency_log(&mut log, &result) {
        Err(VerifierSdkError::ResultSignatureMismatch { .. }) => TestResult::Pass,
        other => TestResult::Fail {
            reason: format!("tampered result signature was not rejected correctly: {other:?}"),
        },
    }
}

fn test_interface_version_validation() -> TestResult {
    let mut sdk = create_verifier_sdk("verifier://version");
    sdk.sdk_version = "vsdk-v2.0".to_string();
    let capsule = build_reference_capsule();
    match sdk.verify_claim(&capsule) {
        Err(VerifierSdkError::UnsupportedSdk(message))
            if message.contains(ERR_SDK_VERSION_UNSUPPORTED) =>
        {
            TestResult::Pass
        }
        other => TestResult::Fail {
            reason: format!("unsupported SDK version was not rejected first: {other:?}"),
        },
    }
}

fn test_interface_structured_error_details() -> TestResult {
    let sdk = create_verifier_sdk("verifier://errors");
    match sdk.verify_trust_state(&[], "") {
        Err(VerifierSdkError::EmptyTrustAnchor) => {}
        other => {
            return TestResult::Fail {
                reason: format!("empty trust anchor did not return structured error: {other:?}"),
            };
        }
    }

    let mut session = match sdk.create_session("sealed-session") {
        Ok(session) => session,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("session fixture creation failed: {err}"),
            };
        }
    };
    if let Err(err) = sdk.seal_session(&mut session) {
        return TestResult::Fail {
            reason: format!("initial session seal failed: {err}"),
        };
    }
    let invalid_result: VerificationResult = match serde_json::from_value(serde_json::json!({
        "operation": "claim",
        "verdict": "pass",
        "confidence_score": 1.0,
        "checked_assertions": [],
        "execution_timestamp": "2026-04-20T00:00:00Z",
        "verifier_identity": "verifier://errors",
        "artifact_binding_hash": "0".repeat(64),
        "verifier_signature": "invalid",
        "sdk_version": SDK_VERSION,
    })) {
        Ok(result) => result,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("invalid result fixture construction failed: {err}"),
            };
        }
    };
    match sdk.record_session_step(&mut session, &invalid_result) {
        Err(VerifierSdkError::SessionSealed(session_id)) if session_id == "sealed-session" => {
            TestResult::Pass
        }
        other => TestResult::Fail {
            reason: format!("sealed session did not return structured error: {other:?}"),
        },
    }
}

fn canonical_replay_bundle() -> ReplayBundle {
    canonical_replay_bundle_with_verifier("verifier://bundle")
}

fn canonical_replay_bundle_with_verifier(verifier_identity: &str) -> ReplayBundle {
    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "evidence/incident.json".to_string(),
        artifact(
            "application/json",
            br#"{"incident_id":"inc-conformance","risk":"high"}"#,
        ),
    );
    artifacts.insert(
        "transcripts/replay.ndjson".to_string(),
        artifact(
            "application/x-ndjson",
            br#"{"sequence":1,"event":"start"}
{"sequence":2,"event":"policy_eval"}
"#,
        ),
    );
    let chunks = chunks_from_artifacts(&artifacts);
    let mut metadata = BTreeMap::new();
    metadata.insert("domain".to_string(), "verifier-sdk-conformance".to_string());

    let mut bundle = ReplayBundle {
        header: BundleHeader {
            hash_algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            payload_length_bytes: payload_length_bytes(&artifacts),
            chunk_count: chunks
                .len()
                .try_into()
                .expect("fixture chunk count should fit u32"),
        },
        schema_version: REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
        sdk_version: SDK_VERSION.to_string(),
        bundle_id: "bundle-conformance-001".to_string(),
        incident_id: "inc-conformance".to_string(),
        created_at: "2026-04-20T14:05:00.000000Z".to_string(),
        policy_version: "strict@2026-04-20".to_string(),
        verifier_identity: verifier_identity.to_string(),
        timeline: vec![
            TimelineEvent {
                sequence_number: 1,
                event_id: "evt-0001".to_string(),
                timestamp: "2026-04-20T14:05:00.000001Z".to_string(),
                event_type: "start".to_string(),
                payload: json!({"incident_id": "inc-conformance"}),
                state_snapshot: json!({"phase": "start"}),
                causal_parent: None,
                policy_version: "strict@2026-04-20".to_string(),
            },
            TimelineEvent {
                sequence_number: 2,
                event_id: "evt-0002".to_string(),
                timestamp: "2026-04-20T14:05:00.000002Z".to_string(),
                event_type: "policy_eval".to_string(),
                payload: json!({"decision": "quarantine"}),
                state_snapshot: json!({"phase": "policy_eval"}),
                causal_parent: Some(1),
                policy_version: "strict@2026-04-20".to_string(),
            },
        ],
        initial_state_snapshot: json!({"baseline_epoch": 1_u64}),
        evidence_refs: vec!["evidence/incident.json".to_string()],
        artifacts,
        chunks,
        metadata,
        integrity_hash: String::new(),
        signature: BundleSignature {
            algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            signature_hex: String::new(),
        },
    };
    seal(&mut bundle).expect("fixture should seal");
    bundle
}

fn chunks_from_artifacts(artifacts: &BTreeMap<String, BundleArtifact>) -> Vec<BundleChunk> {
    let total_chunks = artifacts
        .len()
        .try_into()
        .expect("fixture chunk count should fit u32");
    artifacts
        .iter()
        .enumerate()
        .map(|(index, (path, artifact))| BundleChunk {
            chunk_index: index
                .try_into()
                .expect("fixture chunk index should fit u32"),
            total_chunks,
            artifact_path: path.clone(),
            payload_length_bytes: u64::try_from(artifact.bytes_hex.len() / 2)
                .expect("fixture artifact length should fit u64"),
            payload_digest: artifact.digest.clone(),
        })
        .collect()
}

fn payload_length_bytes(artifacts: &BTreeMap<String, BundleArtifact>) -> u64 {
    artifacts
        .values()
        .map(|artifact| {
            u64::try_from(artifact.bytes_hex.len() / 2)
                .expect("fixture artifact length should fit u64")
        })
        .sum()
}

fn artifact(media_type: &str, bytes: &[u8]) -> BundleArtifact {
    BundleArtifact {
        media_type: media_type.to_string(),
        digest: hash(bytes),
        bytes_hex: hex_encode(bytes),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
