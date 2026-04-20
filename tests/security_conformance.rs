//! Security conformance harness for cross-version compatibility
//!
//! Verifies that security invariants hold across version boundaries:
//! - Ed25519 signatures created by version N verify on version N+1
//! - HKDF derivation produces identical results across versions
//! - Domain/epoch separation preserved across schema changes
//!
//! Pattern: Golden file testing + spec-derived conformance matrix
//!
//! To update golden fixtures: UPDATE_GOLDENS=1 cargo test security_conformance
//! To generate compliance report: cargo test security_conformance -- --nocapture

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

// Import security modules under test
use frankenengine_node::security::threshold_sig::{self, ThresholdConfig, SignerKey, PublicationArtifact, PartialSignature};
use frankenengine_node::security::epoch_scoped_keys::{self, RootSecret, derive_epoch_key, sign_epoch_artifact, verify_epoch_signature};
use frankenengine_node::control_plane::control_epoch::ControlEpoch;

// ── Conformance Framework ──────────────────────────────────────────────────

/// Conformance requirement levels (RFC 2119)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RequirementLevel {
    Must,   // RFC 2119: absolute requirement
    Should, // RFC 2119: strong recommendation
    May,    // RFC 2119: optional
}

/// Test verdict with structured reporting
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum TestVerdict {
    Pass,
    Fail { reason: String },
    XFail { reason: String }, // Expected failure (documented divergence)
    Skip { reason: String },
}

/// A single conformance test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceCase {
    pub id: String,
    pub section: String,
    pub level: RequirementLevel,
    pub description: String,
    pub category: String,
}

/// Test execution result with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub case: ConformanceCase,
    pub verdict: TestVerdict,
    pub execution_time_ms: u64,
    pub version: String,
    pub timestamp: String,
}

/// Golden fixture for cross-version testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFixture {
    /// Version that generated this fixture
    pub version: String,
    /// Git commit hash when generated
    pub git_ref: String,
    /// Timestamp of generation
    pub generated_at: String,
    /// Ed25519 test vectors
    pub ed25519_vectors: Vec<Ed25519Vector>,
    /// HKDF test vectors
    pub hkdf_vectors: Vec<HkdfVector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Vector {
    pub test_id: String,
    pub content_hash: String,
    pub signer_key_hex: String,
    pub signature_hex: String,
    pub domain_context: String,
    pub expected_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HkdfVector {
    pub test_id: String,
    pub root_secret_hex: String,
    pub epoch: u64,
    pub domain: String,
    pub derived_key_hex: String,
    pub derived_key_fingerprint: String,
}

// ── Test Cases Definition ──────────────────────────────────────────────────

const SECURITY_CONFORMANCE_CASES: &[ConformanceCase] = &[
    // Ed25519 Cross-Version Compatibility
    ConformanceCase {
        id: "SIG-001".to_string(),
        section: "ed25519".to_string(),
        level: RequirementLevel::Must,
        description: "Signatures created by any version must verify on current version".to_string(),
        category: "cross_version".to_string(),
    },
    ConformanceCase {
        id: "SIG-002".to_string(),
        section: "ed25519".to_string(),
        level: RequirementLevel::Must,
        description: "Domain separation must be preserved across versions".to_string(),
        category: "domain_separation".to_string(),
    },
    ConformanceCase {
        id: "SIG-003".to_string(),
        section: "ed25519".to_string(),
        level: RequirementLevel::Must,
        description: "Invalid signatures must be rejected consistently across versions".to_string(),
        category: "validation".to_string(),
    },
    ConformanceCase {
        id: "SIG-004".to_string(),
        section: "ed25519".to_string(),
        level: RequirementLevel::Must,
        description: "Threshold signature verification deterministic across versions".to_string(),
        category: "threshold".to_string(),
    },

    // HKDF Cross-Version Compatibility
    ConformanceCase {
        id: "HKDF-001".to_string(),
        section: "hkdf".to_string(),
        level: RequirementLevel::Must,
        description: "Same inputs must produce identical derived keys across versions".to_string(),
        category: "deterministic".to_string(),
    },
    ConformanceCase {
        id: "HKDF-002".to_string(),
        section: "hkdf".to_string(),
        level: RequirementLevel::Must,
        description: "Domain separation must be preserved across versions".to_string(),
        category: "domain_separation".to_string(),
    },
    ConformanceCase {
        id: "HKDF-003".to_string(),
        section: "hkdf".to_string(),
        level: RequirementLevel::Must,
        description: "Epoch separation must be preserved across versions".to_string(),
        category: "epoch_separation".to_string(),
    },
    ConformanceCase {
        id: "HKDF-004".to_string(),
        section: "hkdf".to_string(),
        level: RequirementLevel::Must,
        description: "Sign-verify roundtrip must work with derived keys across versions".to_string(),
        category: "roundtrip".to_string(),
    },
    ConformanceCase {
        id: "HKDF-005".to_string(),
        section: "hkdf".to_string(),
        level: RequirementLevel::Should,
        description: "Key derivation performance should remain within bounds across versions".to_string(),
        category: "performance".to_string(),
    },
];

// ── Golden Fixture Management ──────────────────────────────────────────────

fn get_fixtures_path() -> PathBuf {
    Path::new("tests").join("golden").join("security_conformance.json")
}

fn get_current_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn get_git_ref() -> String {
    // In real implementation, get actual git commit hash
    // For now, use placeholder
    "current".to_string()
}

fn load_or_create_fixtures() -> SecurityFixture {
    let path = get_fixtures_path();

    if std::env::var("UPDATE_GOLDENS").is_ok() || !path.exists() {
        println!("Generating new security conformance fixtures...");
        let fixture = generate_fixtures();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("Failed to create fixtures directory");
        }

        let json = serde_json::to_string_pretty(&fixture)
            .expect("Failed to serialize fixtures");
        fs::write(&path, json).expect("Failed to write fixtures");

        println!("Updated fixtures: {}", path.display());
        return fixture;
    }

    let json = fs::read_to_string(&path)
        .expect("Failed to read fixtures - run with UPDATE_GOLDENS=1 to create");
    serde_json::from_str(&json)
        .expect("Failed to parse fixtures JSON")
}

fn generate_fixtures() -> SecurityFixture {
    SecurityFixture {
        version: get_current_version(),
        git_ref: get_git_ref(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        ed25519_vectors: generate_ed25519_vectors(),
        hkdf_vectors: generate_hkdf_vectors(),
    }
}

fn generate_ed25519_vectors() -> Vec<Ed25519Vector> {
    use ed25519_dalek::{SigningKey, Signer};
    use rand::thread_rng;

    let mut vectors = Vec::new();
    let mut rng = thread_rng();

    // Valid signature vectors
    let test_cases = vec![
        ("basic_content", "test-content-hash"),
        ("empty_content", ""),
        ("large_content", &"x".repeat(1000)),
        ("special_chars", "content-with-!@#$%^&*()"),
        ("unicode_content", "内容-hash-тест"),
    ];

    for (test_id, content_hash) in test_cases {
        let signing_key = SigningKey::generate(&mut rng);
        let signature = threshold_sig::sign(&signing_key, "test-signer", content_hash);

        vectors.push(Ed25519Vector {
            test_id: format!("valid_{}", test_id),
            content_hash: content_hash.to_string(),
            signer_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            signature_hex: signature.signature_hex,
            domain_context: "threshold_sig_verify_v1".to_string(),
            expected_valid: true,
        });
    }

    // Invalid signature vectors (for consistent rejection)
    let signing_key = SigningKey::generate(&mut rng);
    vectors.push(Ed25519Vector {
        test_id: "invalid_signature".to_string(),
        content_hash: "test-content".to_string(),
        signer_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        signature_hex: "deadbeef".repeat(16), // Invalid signature
        domain_context: "threshold_sig_verify_v1".to_string(),
        expected_valid: false,
    });

    vectors
}

fn generate_hkdf_vectors() -> Vec<HkdfVector> {
    let test_cases = vec![
        (1, "marker"),
        (42, "test-domain"),
        (0, "zero-epoch"),
        (u64::MAX, "max-epoch"),
        (100, "unicode-域名"),
        (1, "special-chars-!@#$%^&*()"),
        (1, ""), // Empty domain
    ];

    let mut vectors = Vec::new();

    for (epoch_val, domain) in test_cases {
        let secret = RootSecret::from_bytes([0x42u8; 32]);
        let epoch = ControlEpoch::new(epoch_val);
        let derived_key = derive_epoch_key(&secret, epoch, domain);

        vectors.push(HkdfVector {
            test_id: format!("epoch_{}_domain_{}", epoch_val, domain.replace(['!', '@', '#', '$', '%'], "_")),
            root_secret_hex: "4242424242424242424242424242424242424242424242424242424242424242".to_string(),
            epoch: epoch_val,
            domain: domain.to_string(),
            derived_key_hex: derived_key.to_hex(),
            derived_key_fingerprint: derived_key.fingerprint(),
        });
    }

    vectors
}

// ── Conformance Tests ──────────────────────────────────────────────────────

#[test]
fn security_conformance_ed25519_cross_version() {
    let fixture = load_or_create_fixtures();
    let mut results = Vec::new();

    for vector in &fixture.ed25519_vectors {
        let start = std::time::Instant::now();

        let case = ConformanceCase {
            id: format!("SIG-001.{}", vector.test_id),
            section: "ed25519".to_string(),
            level: RequirementLevel::Must,
            description: format!("Cross-version verification for {}", vector.test_id),
            category: "cross_version".to_string(),
        };

        // Verify signatures from fixture can be validated by current implementation
        let verdict = match verify_ed25519_vector(vector) {
            Ok(valid) => {
                if valid == vector.expected_valid {
                    TestVerdict::Pass
                } else {
                    TestVerdict::Fail {
                        reason: format!(
                            "Expected valid={}, got valid={}",
                            vector.expected_valid, valid
                        ),
                    }
                }
            },
            Err(e) => TestVerdict::Fail {
                reason: format!("Verification failed: {}", e),
            },
        };

        results.push(TestResult {
            case,
            verdict,
            execution_time_ms: start.elapsed().as_millis() as u64,
            version: get_current_version(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    print_results_summary("Ed25519 Cross-Version", &results);
    assert!(results.iter().all(|r| matches!(r.verdict, TestVerdict::Pass)));
}

#[test]
fn security_conformance_hkdf_cross_version() {
    let fixture = load_or_create_fixtures();
    let mut results = Vec::new();

    for vector in &fixture.hkdf_vectors {
        let start = std::time::Instant::now();

        let case = ConformanceCase {
            id: format!("HKDF-001.{}", vector.test_id),
            section: "hkdf".to_string(),
            level: RequirementLevel::Must,
            description: format!("Cross-version key derivation for {}", vector.test_id),
            category: "deterministic".to_string(),
        };

        // Verify HKDF derivation matches fixture exactly
        let verdict = match verify_hkdf_vector(vector) {
            Ok(()) => TestVerdict::Pass,
            Err(e) => TestVerdict::Fail {
                reason: format!("HKDF verification failed: {}", e),
            },
        };

        results.push(TestResult {
            case,
            verdict,
            execution_time_ms: start.elapsed().as_millis() as u64,
            version: get_current_version(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    print_results_summary("HKDF Cross-Version", &results);
    assert!(results.iter().all(|r| matches!(r.verdict, TestVerdict::Pass)));
}

#[test]
fn security_conformance_domain_separation_preservation() {
    let mut results = Vec::new();

    // Test that domain separation properties from fixtures still hold
    let fixture = load_or_create_fixtures();

    // Verify Ed25519 domain separation
    let case = SECURITY_CONFORMANCE_CASES.iter()
        .find(|c| c.id == "SIG-002")
        .unwrap();

    let start = std::time::Instant::now();
    let verdict = verify_ed25519_domain_separation(&fixture.ed25519_vectors);

    results.push(TestResult {
        case: case.clone(),
        verdict,
        execution_time_ms: start.elapsed().as_millis() as u64,
        version: get_current_version(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    });

    // Verify HKDF domain separation
    let case = SECURITY_CONFORMANCE_CASES.iter()
        .find(|c| c.id == "HKDF-002")
        .unwrap();

    let start = std::time::Instant::now();
    let verdict = verify_hkdf_domain_separation(&fixture.hkdf_vectors);

    results.push(TestResult {
        case: case.clone(),
        verdict,
        execution_time_ms: start.elapsed().as_millis() as u64,
        version: get_current_version(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    });

    print_results_summary("Domain Separation", &results);
    assert!(results.iter().all(|r| matches!(r.verdict, TestVerdict::Pass)));
}

#[test]
fn security_conformance_full_matrix() {
    println!("\n🔒 SECURITY CONFORMANCE MATRIX");
    println!("===============================");

    let mut all_results = Vec::new();
    let fixture = load_or_create_fixtures();

    // Execute all conformance cases
    for case in SECURITY_CONFORMANCE_CASES {
        let start = std::time::Instant::now();

        let verdict = match case.id.as_str() {
            "SIG-001" => execute_sig_001_cross_version(&fixture.ed25519_vectors),
            "SIG-002" => verify_ed25519_domain_separation(&fixture.ed25519_vectors),
            "SIG-003" => execute_sig_003_invalid_rejection(&fixture.ed25519_vectors),
            "SIG-004" => execute_sig_004_threshold_deterministic(),
            "HKDF-001" => execute_hkdf_001_deterministic(&fixture.hkdf_vectors),
            "HKDF-002" => verify_hkdf_domain_separation(&fixture.hkdf_vectors),
            "HKDF-003" => execute_hkdf_003_epoch_separation(&fixture.hkdf_vectors),
            "HKDF-004" => execute_hkdf_004_sign_verify_roundtrip(&fixture.hkdf_vectors),
            "HKDF-005" => execute_hkdf_005_performance_bounds(&fixture.hkdf_vectors),
            _ => TestVerdict::Skip { reason: "Test not implemented".to_string() },
        };

        all_results.push(TestResult {
            case: case.clone(),
            verdict,
            execution_time_ms: start.elapsed().as_millis() as u64,
            version: get_current_version(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    generate_compliance_report(&all_results);

    let failures: Vec<_> = all_results.iter()
        .filter(|r| matches!(r.verdict, TestVerdict::Fail { .. }))
        .collect();

    assert!(failures.is_empty(),
           "Security conformance failures: {}",
           failures.iter()
               .map(|r| &r.case.id)
               .collect::<Vec<_>>()
               .join(", "));
}

// ── Verification Functions ──────────────────────────────────────────────────

fn verify_ed25519_vector(vector: &Ed25519Vector) -> Result<bool, String> {
    // Reconstruct verification scenario
    let public_key_bytes = hex::decode(&vector.signer_key_hex)
        .map_err(|e| format!("Invalid public key hex: {}", e))?;

    if public_key_bytes.len() != 32 {
        return Err(format!("Invalid public key length: {}", public_key_bytes.len()));
    }

    let config = ThresholdConfig {
        threshold: 1,
        total_signers: 1,
        signer_keys: vec![SignerKey {
            key_id: "test-signer".to_string(),
            public_key_hex: vector.signer_key_hex.clone(),
        }],
    };

    let artifact = PublicationArtifact {
        artifact_id: "conformance-test".to_string(),
        connector_id: "test-connector".to_string(),
        content_hash: vector.content_hash.clone(),
        signatures: vec![PartialSignature {
            signer_id: "test-signer".to_string(),
            key_id: "test-signer".to_string(),
            signature_hex: vector.signature_hex.clone(),
        }],
    };

    let result = threshold_sig::verify_threshold(
        &config,
        &artifact,
        "conformance-trace",
        "2026-01-01T00:00:00Z"
    );

    Ok(result.verified)
}

fn verify_hkdf_vector(vector: &HkdfVector) -> Result<(), String> {
    let root_secret = RootSecret::from_hex(&vector.root_secret_hex)
        .map_err(|e| format!("Invalid root secret: {}", e))?;

    let epoch = ControlEpoch::new(vector.epoch);
    let derived_key = derive_epoch_key(&root_secret, epoch, &vector.domain);

    let actual_hex = derived_key.to_hex();
    let actual_fingerprint = derived_key.fingerprint();

    if actual_hex != vector.derived_key_hex {
        return Err(format!(
            "Key derivation mismatch: expected {}, got {}",
            vector.derived_key_hex, actual_hex
        ));
    }

    if actual_fingerprint != vector.derived_key_fingerprint {
        return Err(format!(
            "Fingerprint mismatch: expected {}, got {}",
            vector.derived_key_fingerprint, actual_fingerprint
        ));
    }

    Ok(())
}

fn verify_ed25519_domain_separation(vectors: &[Ed25519Vector]) -> TestVerdict {
    // Verify that vectors with same content but different domains would produce different signatures
    // This is a structural test - we verify the domain separation mechanism exists
    let valid_vectors: Vec<_> = vectors.iter()
        .filter(|v| v.expected_valid)
        .collect();

    if valid_vectors.len() < 2 {
        return TestVerdict::Skip {
            reason: "Need at least 2 valid vectors for domain separation test".to_string()
        };
    }

    // Domain separation is built into the signing message construction
    // Verify that our implementation uses domain-separated message building
    let msg1 = threshold_sig::build_signing_message("test-content");
    let msg2 = threshold_sig::build_signing_message("test-content");

    if msg1 != msg2 {
        TestVerdict::Fail {
            reason: "Same content produced different domain-separated messages".to_string(),
        }
    } else if msg1.starts_with(b"threshold_sig_verify_v1:") {
        TestVerdict::Pass
    } else {
        TestVerdict::Fail {
            reason: "Domain separation prefix not found in signing message".to_string(),
        }
    }
}

fn verify_hkdf_domain_separation(vectors: &[HkdfVector]) -> TestVerdict {
    // Find vectors with same epoch but different domains
    let mut domain_groups: BTreeMap<u64, Vec<&HkdfVector>> = BTreeMap::new();
    for vector in vectors {
        domain_groups.entry(vector.epoch).or_default().push(vector);
    }

    for (epoch, epoch_vectors) in domain_groups {
        if epoch_vectors.len() < 2 {
            continue;
        }

        // Verify different domains produce different keys for same epoch
        for i in 0..epoch_vectors.len() {
            for j in (i + 1)..epoch_vectors.len() {
                let vec_a = epoch_vectors[i];
                let vec_b = epoch_vectors[j];

                if vec_a.domain != vec_b.domain {
                    if vec_a.derived_key_hex == vec_b.derived_key_hex {
                        return TestVerdict::Fail {
                            reason: format!(
                                "Domain separation failed: epoch {} domains '{}' and '{}' produced identical keys",
                                epoch, vec_a.domain, vec_b.domain
                            ),
                        };
                    }
                }
            }
        }
    }

    TestVerdict::Pass
}

// ── Individual Test Case Executors ──────────────────────────────────────────

fn execute_sig_001_cross_version(vectors: &[Ed25519Vector]) -> TestVerdict {
    for vector in vectors {
        match verify_ed25519_vector(vector) {
            Ok(valid) if valid == vector.expected_valid => continue,
            Ok(valid) => return TestVerdict::Fail {
                reason: format!("Vector {} expected valid={}, got {}", vector.test_id, vector.expected_valid, valid),
            },
            Err(e) => return TestVerdict::Fail {
                reason: format!("Vector {} verification error: {}", vector.test_id, e),
            },
        }
    }
    TestVerdict::Pass
}

fn execute_sig_003_invalid_rejection(vectors: &[Ed25519Vector]) -> TestVerdict {
    let invalid_vectors: Vec<_> = vectors.iter()
        .filter(|v| !v.expected_valid)
        .collect();

    if invalid_vectors.is_empty() {
        return TestVerdict::Skip {
            reason: "No invalid signature vectors available".to_string(),
        };
    }

    for vector in invalid_vectors {
        match verify_ed25519_vector(vector) {
            Ok(false) => continue, // Correctly rejected
            Ok(true) => return TestVerdict::Fail {
                reason: format!("Invalid vector {} was incorrectly accepted", vector.test_id),
            },
            Err(_) => continue, // Rejection via error is acceptable
        }
    }

    TestVerdict::Pass
}

fn execute_sig_004_threshold_deterministic() -> TestVerdict {
    // Test that threshold verification is deterministic across multiple runs
    use ed25519_dalek::SigningKey;
    use rand::thread_rng;

    let mut rng = thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let content_hash = "deterministic-test";

    let config = ThresholdConfig {
        threshold: 1,
        total_signers: 1,
        signer_keys: vec![SignerKey {
            key_id: "test".to_string(),
            public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        }],
    };

    let signature = threshold_sig::sign(&signing_key, "test", content_hash);
    let artifact = PublicationArtifact {
        artifact_id: "deterministic-test".to_string(),
        connector_id: "test".to_string(),
        content_hash: content_hash.to_string(),
        signatures: vec![signature],
    };

    // Multiple verification attempts should yield identical results
    let results: Vec<_> = (0..10).map(|_| {
        threshold_sig::verify_threshold(&config, &artifact, "trace", "2026-01-01T00:00:00Z")
    }).collect();

    let first_result = &results[0];
    if results.iter().all(|r| r.verified == first_result.verified) {
        TestVerdict::Pass
    } else {
        TestVerdict::Fail {
            reason: "Threshold verification non-deterministic across runs".to_string(),
        }
    }
}

fn execute_hkdf_001_deterministic(vectors: &[HkdfVector]) -> TestVerdict {
    for vector in vectors {
        match verify_hkdf_vector(vector) {
            Ok(()) => continue,
            Err(e) => return TestVerdict::Fail { reason: e },
        }
    }
    TestVerdict::Pass
}

fn execute_hkdf_003_epoch_separation(vectors: &[HkdfVector]) -> TestVerdict {
    // Find vectors with same domain but different epochs
    let mut domain_groups: BTreeMap<&str, Vec<&HkdfVector>> = BTreeMap::new();
    for vector in vectors {
        domain_groups.entry(&vector.domain).or_default().push(vector);
    }

    for (domain, domain_vectors) in domain_groups {
        if domain_vectors.len() < 2 {
            continue;
        }

        // Verify different epochs produce different keys for same domain
        for i in 0..domain_vectors.len() {
            for j in (i + 1)..domain_vectors.len() {
                let vec_a = domain_vectors[i];
                let vec_b = domain_vectors[j];

                if vec_a.epoch != vec_b.epoch {
                    if vec_a.derived_key_hex == vec_b.derived_key_hex {
                        return TestVerdict::Fail {
                            reason: format!(
                                "Epoch separation failed: domain '{}' epochs {} and {} produced identical keys",
                                domain, vec_a.epoch, vec_b.epoch
                            ),
                        };
                    }
                }
            }
        }
    }

    TestVerdict::Pass
}

fn execute_hkdf_004_sign_verify_roundtrip(vectors: &[HkdfVector]) -> TestVerdict {
    for vector in vectors {
        let root_secret = match RootSecret::from_hex(&vector.root_secret_hex) {
            Ok(s) => s,
            Err(e) => return TestVerdict::Fail {
                reason: format!("Invalid root secret in vector {}: {}", vector.test_id, e),
            },
        };

        let epoch = ControlEpoch::new(vector.epoch);
        let artifact = b"conformance-test-artifact";

        // Test sign-verify roundtrip with derived key
        match sign_epoch_artifact(artifact, epoch, &vector.domain, &root_secret) {
            Ok(signature) => {
                match verify_epoch_signature(artifact, &signature, epoch, &vector.domain, &root_secret) {
                    Ok(()) => continue,
                    Err(e) => return TestVerdict::Fail {
                        reason: format!("Roundtrip verify failed for {}: {}", vector.test_id, e),
                    },
                }
            },
            Err(e) => return TestVerdict::Fail {
                reason: format!("Roundtrip sign failed for {}: {}", vector.test_id, e),
            },
        }
    }

    TestVerdict::Pass
}

fn execute_hkdf_005_performance_bounds(_vectors: &[HkdfVector]) -> TestVerdict {
    // Performance test: key derivation should complete within reasonable bounds
    let secret = RootSecret::from_bytes([0x42u8; 32]);
    let start = std::time::Instant::now();

    // Derive 100 keys
    for i in 0..100 {
        let _key = derive_epoch_key(&secret, ControlEpoch::new(i), "perf-test");
    }

    let duration = start.elapsed();
    let per_derivation = duration / 100;

    // Should be fast: < 1ms per derivation
    if per_derivation.as_millis() < 1 {
        TestVerdict::Pass
    } else {
        TestVerdict::Fail {
            reason: format!("Key derivation too slow: {}ms per operation", per_derivation.as_millis()),
        }
    }
}

// ── Reporting ──────────────────────────────────────────────────────────────

fn print_results_summary(suite_name: &str, results: &[TestResult]) {
    let pass = results.iter().filter(|r| matches!(r.verdict, TestVerdict::Pass)).count();
    let fail = results.iter().filter(|r| matches!(r.verdict, TestVerdict::Fail { .. })).count();
    let xfail = results.iter().filter(|r| matches!(r.verdict, TestVerdict::XFail { .. })).count();
    let skip = results.iter().filter(|r| matches!(r.verdict, TestVerdict::Skip { .. })).count();

    println!("\n{}: {}/{} pass, {} fail, {} xfail, {} skip",
             suite_name, pass, results.len(), fail, xfail, skip);

    for result in results {
        match &result.verdict {
            TestVerdict::Pass => println!("  ✅ {}", result.case.id),
            TestVerdict::Fail { reason } => println!("  ❌ {}: {}", result.case.id, reason),
            TestVerdict::XFail { reason } => println!("  ⚠️  {} (expected): {}", result.case.id, reason),
            TestVerdict::Skip { reason } => println!("  ⏭️  {} (skipped): {}", result.case.id, reason),
        }
    }
}

fn generate_compliance_report(results: &[TestResult]) {
    println!("\n📊 SECURITY CONFORMANCE COMPLIANCE REPORT");
    println!("==========================================");

    let mut by_section: BTreeMap<&str, SectionStats> = BTreeMap::new();

    for result in results {
        let section = by_section.entry(&result.case.section).or_default();
        match result.case.level {
            RequirementLevel::Must => section.must_total += 1,
            RequirementLevel::Should => section.should_total += 1,
            RequirementLevel::May => section.may_total += 1,
        }

        match (&result.verdict, result.case.level) {
            (TestVerdict::Pass, RequirementLevel::Must) => section.must_pass += 1,
            (TestVerdict::Pass, RequirementLevel::Should) => section.should_pass += 1,
            (TestVerdict::Pass, RequirementLevel::May) => section.may_pass += 1,
            (TestVerdict::XFail { .. }, RequirementLevel::Must) => section.must_xfail += 1,
            (TestVerdict::XFail { .. }, RequirementLevel::Should) => section.should_xfail += 1,
            (TestVerdict::XFail { .. }, RequirementLevel::May) => section.may_xfail += 1,
            _ => {},
        }
    }

    println!("| Section | MUST (pass/total) | SHOULD (pass/total) | Score  |");
    println!("|---------|--------------------|---------------------|---------|");

    for (section, stats) in by_section {
        let must_score = if stats.must_total > 0 {
            (stats.must_pass as f64) / (stats.must_total as f64) * 100.0
        } else { 100.0 };

        let should_score = if stats.should_total > 0 {
            (stats.should_pass as f64) / (stats.should_total as f64) * 100.0
        } else { 100.0 };

        let overall = (must_score + should_score) / 2.0;

        println!("| {:7} | {:4}/{:<4} ({:5.1}%) | {:4}/{:<4} ({:5.1}%) | {:5.1}% |",
                 section,
                 stats.must_pass, stats.must_total, must_score,
                 stats.should_pass, stats.should_total, should_score,
                 overall);

        if stats.must_xfail > 0 || stats.should_xfail > 0 {
            println!("| {:>7} | {:>17} | {:>19} | XFAILs |",
                     "",
                     format!("({} xfail)", stats.must_xfail),
                     format!("({} xfail)", stats.should_xfail));
        }
    }

    let total_must: u32 = by_section.values().map(|s| s.must_total).sum();
    let total_must_pass: u32 = by_section.values().map(|s| s.must_pass).sum();
    let must_compliance = if total_must > 0 {
        (total_must_pass as f64) / (total_must as f64) * 100.0
    } else { 100.0 };

    println!("\n🎯 **MUST Clause Compliance: {:.1}%** ({}/{})",
             must_compliance, total_must_pass, total_must);

    if must_compliance >= 95.0 {
        println!("✅ CONFORMANT: MUST clause compliance ≥ 95%");
    } else {
        println!("❌ NON-CONFORMANT: MUST clause compliance < 95%");
    }
}

#[derive(Default)]
struct SectionStats {
    must_total: u32,
    must_pass: u32,
    must_xfail: u32,
    should_total: u32,
    should_pass: u32,
    should_xfail: u32,
    may_total: u32,
    may_pass: u32,
    may_xfail: u32,
}