#!/usr/bin/env cargo
//! bd-83lv0: Profile manipulation attack prevention conformance harness.
//!
//! Tests explicit allowlist enforcement with no silent fallback to ensure runtime
//! profile parsing rejects all invalid input including packaging profile confusion
//! and various manipulation attempts with clear, actionable error messages.

use std::str::FromStr;
use std::time::{Duration, Instant};

use frankenengine_node::config::Profile;

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Test that a profile parse fails with expected error patterns.
fn assert_profile_parse_fails(input: &str, expected_patterns: &[&str]) -> Result<(), String> {
    match Profile::from_str(input) {
        Ok(profile) => Err(format!(
            "Expected profile '{}' to fail parsing, but got: {:?}",
            input, profile
        )),
        Err(err) => {
            let error_msg = err.to_string();
            for pattern in expected_patterns {
                if !error_msg.contains(pattern) {
                    return Err(format!(
                        "Error message for '{}' missing expected pattern '{}'\nActual error: {}",
                        input, pattern, error_msg
                    ));
                }
            }
            Ok(())
        }
    }
}

/// Test that a profile parse succeeds with expected result.
fn assert_profile_parse_succeeds(input: &str, expected: Profile) -> Result<(), String> {
    match Profile::from_str(input) {
        Ok(actual) => {
            if actual == expected {
                Ok(())
            } else {
                Err(format!(
                    "Profile '{}' parsed to {:?}, expected {:?}",
                    input, actual, expected
                ))
            }
        }
        Err(err) => Err(format!(
            "Expected profile '{}' to parse successfully, but got error: {}",
            input, err
        )),
    }
}

// ---------------------------------------------------------------------------
// bd-83lv0 Core Security Tests - Allowlist Enforcement
// ---------------------------------------------------------------------------

fn test_allowlist_valid_profiles_accepted() -> Result<(), String> {
    println!("TEST: Valid profiles from explicit allowlist accepted");

    let valid_cases = [
        ("strict", Profile::Strict),
        ("balanced", Profile::Balanced),
        ("legacy-risky", Profile::LegacyRisky),
    ];

    for (input, expected) in valid_cases.iter() {
        assert_profile_parse_succeeds(input, *expected)?;
        println!("  ✓ '{}' → {:?}", input, expected);
    }

    println!("✓ All valid profiles accepted");
    Ok(())
}

fn test_allowlist_invalid_profiles_hard_rejected() -> Result<(), String> {
    println!("TEST: Invalid profiles hard-rejected with no fallback");

    let invalid_profiles = [
        "invalid",
        "INVALID",
        "garbage",
        "null",
        "undefined",
        "strict-mode",
        "balanced-mode",
        "legacy",
        "risky",
        "security",
        "performance",
        "default",
        "auto",
        "production",
        "development",
        "test",
    ];

    for profile in invalid_profiles.iter() {
        assert_profile_parse_fails(
            profile,
            &[
                "Invalid runtime profile",
                "Must be one of: strict, balanced, legacy-risky",
                "No fallback will be applied",
            ],
        )?;
        println!("  ✓ '{}' correctly rejected", profile);
    }

    println!("✓ All invalid profiles hard-rejected");
    Ok(())
}

fn test_allowlist_no_silent_fallback_enforcement() -> Result<(), String> {
    println!("TEST: No silent fallback - all failures are explicit errors");

    let manipulation_attempts = [
        "",              // Empty
        " ",             // Whitespace only
        "strictt",       // Typo
        "balancced",     // Typo
        "legaacy-risky", // Typo
        "strict ",       // Trailing space
        " balanced",     // Leading space
        "strict-risky",  // Invalid combination
        "legacy_risky",  // Underscore (should be normalized but still tested)
        "STRICT",        // Wrong case (should be normalized but still tested)
        "Balanced",      // Mixed case
    ];

    for attempt in manipulation_attempts.iter() {
        match Profile::from_str(attempt) {
            Ok(_) => {
                // Some might succeed due to normalization - that's OK, but verify it's correct
                let normalized = attempt.trim().to_ascii_lowercase().replace('_', "-");
                if !["strict", "balanced", "legacy-risky"].contains(&normalized.as_str()) {
                    return Err(format!(
                        "Profile '{}' should have been rejected but was accepted",
                        attempt
                    ));
                }
            }
            Err(err) => {
                let error_msg = err.to_string();
                if error_msg.contains("fallback") || error_msg.to_lowercase().contains("default") {
                    return Err(format!(
                        "Error message for '{}' suggests fallback behavior: {}",
                        attempt, error_msg
                    ));
                }
                if !error_msg.contains("Must be one of:") {
                    return Err(format!(
                        "Error message for '{}' doesn't list valid options: {}",
                        attempt, error_msg
                    ));
                }
            }
        }
        println!("  ✓ '{}' handled correctly (no silent fallback)", attempt);
    }

    println!("✓ No silent fallback behavior detected");
    Ok(())
}

// ---------------------------------------------------------------------------
// bd-2zped Packaging Profile Confusion Prevention Tests
// ---------------------------------------------------------------------------

fn test_packaging_profile_confusion_detection() -> Result<(), String> {
    println!("TEST: Packaging profile confusion detected and explained");

    let packaging_profiles = ["local", "dev", "enterprise"];

    for profile in packaging_profiles.iter() {
        assert_profile_parse_fails(
            profile,
            &[
                "Invalid runtime profile",
                "appears to be a packaging profile name",
                "Runtime profiles (--profile) control security/compatibility behavior",
                "Packaging profiles",
                "are used during build/release",
                "packaging/profiles.toml",
            ],
        )?;
        println!("  ✓ '{}' identified as packaging profile with helpful error", profile);
    }

    println!("✓ Packaging profile confusion correctly detected");
    Ok(())
}

fn test_packaging_profile_case_normalization() -> Result<(), String> {
    println!("TEST: Packaging profiles detected after case normalization");

    let case_variants = [
        ("LOCAL", "local"),
        ("Dev", "dev"),
        ("ENTERPRISE", "enterprise"),
        ("Local", "local"),
        ("DEV", "dev"),
        ("Enterprise", "enterprise"),
    ];

    for (input, canonical) in case_variants.iter() {
        assert_profile_parse_fails(
            input,
            &[
                "Invalid runtime profile",
                "appears to be a packaging profile name",
                canonical, // Should reference the canonical form
            ],
        )?;
        println!("  ✓ '{}' normalized to '{}' and detected as packaging profile", input, canonical);
    }

    println!("✓ Packaging profile detection works after normalization");
    Ok(())
}

// ---------------------------------------------------------------------------
// Profile Normalization and Case Handling Tests
// ---------------------------------------------------------------------------

fn test_case_insensitive_valid_profiles() -> Result<(), String> {
    println!("TEST: Valid profiles accepted with case normalization");

    let case_variants = [
        ("STRICT", Profile::Strict),
        ("Strict", Profile::Strict),
        ("BALANCED", Profile::Balanced),
        ("Balanced", Profile::Balanced),
        ("LEGACY-RISKY", Profile::LegacyRisky),
        ("Legacy-Risky", Profile::LegacyRisky),
        ("legacy-RISKY", Profile::LegacyRisky),
    ];

    for (input, expected) in case_variants.iter() {
        assert_profile_parse_succeeds(input, *expected)?;
        println!("  ✓ '{}' normalized to {:?}", input, expected);
    }

    println!("✓ Case normalization working for valid profiles");
    Ok(())
}

fn test_whitespace_trimming() -> Result<(), String> {
    println!("TEST: Whitespace trimming in profile parsing");

    let whitespace_cases = [
        (" strict", Profile::Strict),
        ("strict ", Profile::Strict),
        (" balanced ", Profile::Balanced),
        ("\tlegacy-risky\t", Profile::LegacyRisky),
        ("\n strict \n", Profile::Strict),
    ];

    for (input, expected) in whitespace_cases.iter() {
        assert_profile_parse_succeeds(input, *expected)?;
        println!("  ✓ '{}' trimmed and accepted", input.escape_debug());
    }

    println!("✓ Whitespace trimming working correctly");
    Ok(())
}

fn test_underscore_to_dash_normalization() -> Result<(), String> {
    println!("TEST: Underscore to dash normalization");

    let underscore_cases = [
        ("legacy_risky", Profile::LegacyRisky),
        ("LEGACY_RISKY", Profile::LegacyRisky),
        ("Legacy_Risky", Profile::LegacyRisky),
    ];

    for (input, expected) in underscore_cases.iter() {
        assert_profile_parse_succeeds(input, *expected)?;
        println!("  ✓ '{}' normalized to {:?}", input, expected);
    }

    println!("✓ Underscore normalization working correctly");
    Ok(())
}

// ---------------------------------------------------------------------------
// Security Attack Vector Tests
// ---------------------------------------------------------------------------

fn test_injection_attempt_rejection() -> Result<(), String> {
    println!("TEST: Injection and special character attempts rejected");

    let injection_attempts = [
        "strict;balanced",     // Command injection attempt
        "strict\nbalanced",    // Newline injection
        "strict\x00balanced",  // Null byte injection
        "strict%00balanced",   // URL encoding
        "strict\\nbalanced",   // Escape sequence
        "strict\rbalanced",    // Carriage return
        "../strict",           // Path traversal attempt
        "strict$(echo)",       // Command substitution
        "strict`echo`",        // Backtick command substitution
        "strict${balanced}",   // Variable expansion
        "strict||balanced",    // Command chaining
        "strict&&balanced",    // Command chaining
        "'strict'",            // Shell quoting
        "\"balanced\"",        // Shell quoting
        "strict\tbalanced",    // Tab injection
    ];

    for attempt in injection_attempts.iter() {
        assert_profile_parse_fails(
            attempt,
            &[
                "Invalid runtime profile",
                "Must be one of:",
            ],
        )?;
        println!("  ✓ '{}' injection attempt rejected", attempt.escape_debug());
    }

    println!("✓ All injection attempts correctly rejected");
    Ok(())
}

fn test_unicode_and_encoding_attacks() -> Result<(), String> {
    println!("TEST: Unicode and encoding attack vectors rejected");

    let unicode_attacks = [
        "ｓｔｒｉｃｔ",        // Fullwidth characters
        "strict\u{200B}",      // Zero-width space
        "strict\u{FEFF}",      // Byte order mark
        "strict\u{202E}",      // Right-to-left override
        "ѕtrict",              // Cyrillic s (homoglyph)
        "bаlanced",            // Cyrillic a (homoglyph)
        "strict\u{0301}",      // Combining accent
        "strict․balanced",      // One dot leader (looks like period)
        "strict‒balanced",     // Figure dash (looks like hyphen)
        "strict−balanced",     // Minus sign (looks like hyphen)
    ];

    for attempt in unicode_attacks.iter() {
        assert_profile_parse_fails(
            attempt,
            &[
                "Invalid runtime profile",
                "Must be one of:",
            ],
        )?;
        println!("  ✓ Unicode attack '{}' rejected", attempt.escape_debug());
    }

    println!("✓ All Unicode attack vectors correctly rejected");
    Ok(())
}

fn test_length_boundary_attacks() -> Result<(), String> {
    println!("TEST: Length boundary attack vectors");

    // Very long inputs
    let long_profile = "x".repeat(1000);
    assert_profile_parse_fails(
        &long_profile,
        &["Invalid runtime profile", "Must be one of:"],
    )?;
    println!("  ✓ Very long input (1000 chars) rejected");

    // Very long valid prefix with invalid suffix
    let long_invalid = format!("strict{}", "x".repeat(995));
    assert_profile_parse_fails(
        &long_invalid,
        &["Invalid runtime profile"],
    )?;
    println!("  ✓ Long input with valid prefix rejected");

    println!("✓ Length boundary attacks handled correctly");
    Ok(())
}

// ---------------------------------------------------------------------------
// Error Message Quality Tests
// ---------------------------------------------------------------------------

fn test_error_message_quality() -> Result<(), String> {
    println!("TEST: Error message quality and actionability");

    // Test error message contains all required information
    match Profile::from_str("invalid") {
        Ok(_) => return Err("Expected 'invalid' to fail".to_string()),
        Err(err) => {
            let msg = err.to_string();

            let required_elements = [
                "Invalid runtime profile 'invalid'",  // Quotes the input
                "Must be one of: strict, balanced, legacy-risky",  // Lists valid options
                "No fallback will be applied",  // Explicit no-fallback statement
            ];

            for element in required_elements.iter() {
                if !msg.contains(element) {
                    return Err(format!(
                        "Error message missing required element: '{}'\nFull message: {}",
                        element, msg
                    ));
                }
            }

            println!("  ✓ Error message contains all required elements");
        }
    }

    // Test packaging profile error message quality
    match Profile::from_str("dev") {
        Ok(_) => return Err("Expected 'dev' to fail".to_string()),
        Err(err) => {
            let msg = err.to_string();

            let required_elements = [
                "Invalid runtime profile 'dev'",  // Quotes the input
                "appears to be a packaging profile name",  // Explains the mistake
                "Runtime profiles (--profile) control security/compatibility behavior",  // Educational
                "must be one of: strict, balanced, legacy-risky",  // Lists valid runtime profiles
                "Packaging profiles (local, dev, enterprise)",  // Lists packaging profiles
                "packaging/profiles.toml",  // Points to relevant documentation
            ];

            for element in required_elements.iter() {
                if !msg.contains(element) {
                    return Err(format!(
                        "Packaging error message missing required element: '{}'\nFull message: {}",
                        element, msg
                    ));
                }
            }

            println!("  ✓ Packaging profile error message comprehensive");
        }
    }

    println!("✓ Error messages are high quality and actionable");
    Ok(())
}

// ---------------------------------------------------------------------------
// Performance and Robustness Tests
// ---------------------------------------------------------------------------

fn test_performance_parsing_overhead() -> Result<(), String> {
    println!("TEST: Profile parsing performance");

    let test_inputs = [
        "strict", "balanced", "legacy-risky",  // Valid
        "invalid", "garbage", "dev", "local", "enterprise",  // Invalid
    ];

    let start = Instant::now();
    for _ in 0..1000 {
        for input in test_inputs.iter() {
            let _ = Profile::from_str(input);
        }
    }
    let duration = start.elapsed();

    println!("  Performance: 8000 profile parses in {:?}", duration);

    if duration > Duration::from_millis(10) {
        return Err(format!(
            "Performance regression: profile parsing took {:?} for 8000 operations",
            duration
        ));
    }

    println!("✓ Profile parsing performance acceptable");
    Ok(())
}

fn test_robustness_extreme_inputs() -> Result<(), String> {
    println!("TEST: Robustness with extreme inputs");

    let extreme_inputs = [
        "",                    // Empty
        " ".repeat(100),       // Only whitespace
        "\0",                  // Null byte
        "\x01\x02\x03",       // Control characters
        "🚀🔥💻",              // Emoji
        "strict\r\nbalanced", // Mixed line endings
        &"x".repeat(10000),   // Very long
    ];

    for input in extreme_inputs.iter() {
        // Should not panic, regardless of result
        match Profile::from_str(input) {
            Ok(profile) => {
                // If it succeeds, it should only be for valid normalized forms
                match input.trim().to_ascii_lowercase().replace('_', "-").as_str() {
                    "strict" | "balanced" | "legacy-risky" => {
                        println!("  ✓ '{}' correctly accepted as valid", input.escape_debug());
                    }
                    _ => {
                        return Err(format!(
                            "Extreme input '{}' incorrectly accepted as {:?}",
                            input.escape_debug(), profile
                        ));
                    }
                }
            }
            Err(_) => {
                println!("  ✓ '{}' correctly rejected", input.escape_debug());
            }
        }
    }

    println!("✓ All extreme inputs handled robustly");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main Conformance Runner
// ---------------------------------------------------------------------------

fn main() {
    println!("bd-83lv0: Profile Security Conformance Harness");
    println!("===============================================");

    let mut tests_run = 0;
    let mut tests_passed = 0;
    let mut failures = Vec::new();

    let test_cases = vec![
        ("bd-83lv0: Valid profiles from allowlist accepted", test_allowlist_valid_profiles_accepted as fn() -> Result<(), String>),
        ("bd-83lv0: Invalid profiles hard-rejected with no fallback", test_allowlist_invalid_profiles_hard_rejected),
        ("bd-83lv0: No silent fallback enforcement", test_allowlist_no_silent_fallback_enforcement),
        ("bd-2zped: Packaging profile confusion detection", test_packaging_profile_confusion_detection),
        ("bd-2zped: Packaging profile case normalization", test_packaging_profile_case_normalization),
        ("NORMALIZATION: Case insensitive valid profiles", test_case_insensitive_valid_profiles),
        ("NORMALIZATION: Whitespace trimming", test_whitespace_trimming),
        ("NORMALIZATION: Underscore to dash conversion", test_underscore_to_dash_normalization),
        ("SECURITY: Injection attempt rejection", test_injection_attempt_rejection),
        ("SECURITY: Unicode and encoding attack vectors", test_unicode_and_encoding_attacks),
        ("SECURITY: Length boundary attack vectors", test_length_boundary_attacks),
        ("ERROR-QUALITY: Message actionability and completeness", test_error_message_quality),
        ("PERF-REGRESSION: Profile parsing performance", test_performance_parsing_overhead),
        ("ROBUSTNESS: Extreme input handling", test_robustness_extreme_inputs),
    ];

    for (test_name, test_fn) in test_cases {
        tests_run += 1;
        println!("\n[{}] {}", tests_run, test_name);

        match test_fn() {
            Ok(()) => {
                tests_passed += 1;
                println!("✅ PASS");
            }
            Err(reason) => {
                failures.push((test_name, reason.clone()));
                println!("❌ FAIL: {}", reason);
            }
        }
    }

    println!("\n===============================================");
    println!("bd-83lv0 Conformance Results");
    println!("Passed: {}/{}", tests_passed, tests_run);

    if failures.is_empty() {
        println!("✅ ALL CONFORMANCE TESTS PASSED");
        println!("\n🔒 SECURITY VALIDATION COMPLETE:");
        println!("  • Profile manipulation attacks prevented");
        println!("  • Explicit allowlist enforced with no fallback");
        println!("  • Packaging profile confusion detected");
        println!("  • Injection and encoding attacks blocked");
        println!("  • Error messages provide actionable guidance");
        std::process::exit(0);
    } else {
        println!("❌ {} FAILURES:", failures.len());
        for (test_name, reason) in failures {
            println!("  - {}: {}", test_name, reason);
        }
        std::process::exit(1);
    }
}