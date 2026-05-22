#!/usr/bin/env cargo
//! bd-3ku8: Extension artifact capability contract conformance harness.
//!
//! Tests fail-closed admission and runtime enforcement of capability-carrying
//! extension artifacts to ensure contract integrity and prevent capability drift.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_node::extensions::artifact_contract::{
    ArtifactContract, CapabilityToken, ExtensionArtifact,
    SCHEMA_VERSION, ARTIFACT_TOKEN_INPUT_POLICY, ARTIFACT_CAPABILITY_LIST_POLICY,
};

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

fn valid_capability_token(name: &str) -> CapabilityToken {
    CapabilityToken::new(name).expect("valid capability token")
}

fn valid_artifact(id: &str, capabilities: &[&str]) -> ExtensionArtifact {
    let mut artifact = ExtensionArtifact::new(id, "test-extension", "1.0.0");
    for cap in capabilities {
        artifact.add_capability(valid_capability_token(cap));
    }
    artifact
}

// ---------------------------------------------------------------------------
// Capability Contract Admission Tests
// ---------------------------------------------------------------------------

fn test_valid_contracts_admitted() -> Result<(), String> {
    println!("TEST: Valid capability contracts admitted");

    let test_cases = [
        (vec!["fs.read", "fs.write"], "file system access"),
        (vec!["net.http.client"], "network client access"),
        (vec!["crypto.hash", "crypto.sign"], "cryptographic operations"),
        (vec![], "no capabilities required"),
    ];

    for (capabilities, description) in test_cases.iter() {
        let artifact = valid_artifact("test-ext", capabilities);

        match artifact.validate_contract() {
            Ok(_) => println!("  ✓ {} - contract valid", description),
            Err(err) => {
                return Err(format!(
                    "Valid contract rejected for {}: {}",
                    description, err
                ));
            }
        }
    }

    println!("✓ All valid contracts admitted");
    Ok(())
}

fn test_invalid_contracts_rejected() -> Result<(), String> {
    println!("TEST: Invalid contracts fail-closed rejection");

    // Empty artifact ID
    let mut invalid_empty = ExtensionArtifact::new("", "test", "1.0.0");
    invalid_empty.add_capability(valid_capability_token("fs.read"));

    if invalid_empty.validate_contract().is_ok() {
        return Err("Empty artifact ID should be rejected".to_string());
    }
    println!("  ✓ Empty artifact ID rejected");

    // Reserved artifact ID
    let mut invalid_reserved = ExtensionArtifact::new("<unknown>", "test", "1.0.0");
    invalid_reserved.add_capability(valid_capability_token("fs.read"));

    if invalid_reserved.validate_contract().is_ok() {
        return Err("Reserved artifact ID should be rejected".to_string());
    }
    println!("  ✓ Reserved artifact ID rejected");

    // Too many capabilities
    let mut invalid_too_many = ExtensionArtifact::new("test", "test", "1.0.0");
    for i in 0..1000 {  // Exceed MAX_CAPABILITIES_PER_CONTRACT
        invalid_too_many.add_capability(valid_capability_token(&format!("cap.{}", i)));
    }

    if invalid_too_many.validate_contract().is_ok() {
        return Err("Too many capabilities should be rejected".to_string());
    }
    println!("  ✓ Excessive capabilities rejected");

    println!("✓ All invalid contracts properly rejected");
    Ok(())
}

// ---------------------------------------------------------------------------
// Runtime Enforcement Tests
// ---------------------------------------------------------------------------

fn test_contract_enforcement_no_drift() -> Result<(), String> {
    println!("TEST: Runtime enforcement prevents capability drift");

    let original_caps = vec!["fs.read", "net.http.client"];
    let artifact = valid_artifact("drift-test", &original_caps);

    // Simulate runtime with same capabilities - should pass
    let runtime_caps: BTreeSet<_> = original_caps.iter().map(|s| s.to_string()).collect();

    if !artifact.check_runtime_compliance(&runtime_caps) {
        return Err("Matching capabilities should pass compliance".to_string());
    }
    println!("  ✓ Matching capabilities pass compliance");

    // Simulate runtime with extra capabilities - should fail
    let mut extra_caps = runtime_caps.clone();
    extra_caps.insert("crypto.sign".to_string());

    if artifact.check_runtime_compliance(&extra_caps) {
        return Err("Extra capabilities should fail compliance".to_string());
    }
    println!("  ✓ Extra capabilities fail compliance (drift detected)");

    // Simulate runtime with missing capabilities - should fail
    let missing_caps: BTreeSet<_> = vec!["fs.read".to_string()].into_iter().collect();

    if artifact.check_runtime_compliance(&missing_caps) {
        return Err("Missing capabilities should fail compliance".to_string());
    }
    println!("  ✓ Missing capabilities fail compliance");

    println!("✓ Runtime enforcement prevents capability drift");
    Ok(())
}

// ---------------------------------------------------------------------------
// Capability Token Validation Tests
// ---------------------------------------------------------------------------

fn test_capability_token_validation() -> Result<(), String> {
    println!("TEST: Capability token validation");

    let valid_tokens = [
        "fs.read",
        "fs.write",
        "net.http.client",
        "net.tcp.server",
        "crypto.hash.sha256",
        "runtime.eval.restricted",
    ];

    for token in valid_tokens.iter() {
        match CapabilityToken::new(token) {
            Ok(_) => println!("  ✓ '{}' accepted", token),
            Err(err) => {
                return Err(format!("Valid token '{}' rejected: {}", token, err));
            }
        }
    }

    let invalid_tokens = [
        "",           // Empty
        " fs.read",   // Leading space
        "fs.read ",   // Trailing space
        "fs..read",   // Double dot
        "fs.read..",  // Trailing dots
        "FS.READ",    // Wrong case
        "fs/read",    // Slash instead of dot
        "fs_read",    // Underscore
    ];

    for token in invalid_tokens.iter() {
        match CapabilityToken::new(token) {
            Ok(_) => {
                return Err(format!("Invalid token '{}' should be rejected", token));
            }
            Err(_) => println!("  ✓ '{}' correctly rejected", token),
        }
    }

    println!("✓ Capability token validation working");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main Conformance Runner
// ---------------------------------------------------------------------------

fn main() {
    println!("bd-3ku8: Extension Artifact Contract Conformance Harness");
    println!("=======================================================");

    let mut tests_run = 0;
    let mut tests_passed = 0;
    let mut failures = Vec::new();

    let test_cases = vec![
        ("ADMISSION: Valid contracts admitted", test_valid_contracts_admitted as fn() -> Result<(), String>),
        ("ADMISSION: Invalid contracts fail-closed rejection", test_invalid_contracts_rejected),
        ("ENFORCEMENT: Runtime compliance prevents drift", test_contract_enforcement_no_drift),
        ("VALIDATION: Capability token format validation", test_capability_token_validation),
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

    println!("\n=======================================================");
    println!("bd-3ku8 Conformance Results");
    println!("Passed: {}/{}", tests_passed, tests_run);

    if failures.is_empty() {
        println!("✅ ALL CONFORMANCE TESTS PASSED");
        println!("\n🔒 EXTENSION SECURITY COMPLETE:");
        println!("  • Capability contracts fail-closed admission");
        println!("  • Runtime enforcement prevents capability drift");
        println!("  • Token validation ensures proper capability format");
        std::process::exit(0);
    } else {
        println!("❌ {} FAILURES:", failures.len());
        for (test_name, reason) in failures {
            println!("  - {}: {}", test_name, reason);
        }
        std::process::exit(1);
    }
}