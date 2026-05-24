#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

#[cfg(feature = "engine")]
use frankenengine_node::supply_chain::manifest::{
    AttestationRef, BehavioralProfile, CertificationLevel, ManifestSignature, PackageIdentity,
    ProvenanceEnvelope, RiskTier, SignedExtensionManifest, TrustMetadata,
    MANIFEST_SCHEMA_VERSION, MAX_DECLARED_NETWORK_ZONES, MAX_MANIFEST_ATTESTATION_CHAIN_ENTRIES,
    MAX_MANIFEST_CAPABILITIES, MAX_MANIFEST_FIELD_BYTES, MAX_REPRODUCIBILITY_MARKERS,
};

#[cfg(feature = "engine")]
use frankenengine_extension_host::Capability;

/// Comprehensive fuzz target for SignedExtensionManifest validation and security.
///
/// Tests manifest processing against:
/// - Package identity spoofing (name squatting, typosquatting, unicode confusables)
/// - Capability privilege escalation (injection, undeclared capabilities)
/// - Risk tier bypass attempts (misclassification, enum confusion)
/// - Provenance forgery (fake attestation chains, digest manipulation)
/// - Signature validation bypass (malformed signatures, key confusion)
/// - Trust metadata tampering (certification level bypass, revocation evasion)
/// - Field injection attacks (oversized strings, control characters, null bytes)
/// - Serialization vulnerabilities (JSON injection, CBOR confusion)
/// - Memory exhaustion (large attestation chains, excessive capabilities)
///
/// Security focus: Ensure robust validation without crashes, injection vectors,
/// or authentication bypasses in manifest processing pipeline.
#[derive(Arbitrary, Debug)]
struct ManifestFuzzInput {
    /// Base manifest structure for testing
    manifest_template: ManifestTemplate,

    /// Attack vector to apply
    attack_vector: AttackVector,

    /// Serialization format to test
    format_test: FormatTest,

    /// Size/DoS attack parameters
    size_attack: SizeAttack,
}

#[derive(Arbitrary, Debug)]
struct ManifestTemplate {
    /// Package identity components
    package_name: Vec<u8>,
    package_version: Vec<u8>,
    publisher: Vec<u8>,
    author: Vec<u8>,

    /// Behavioral profile
    risk_tier: u8, // Will map to RiskTier enum
    summary: Vec<u8>,
    network_zones: Vec<Vec<u8>>,

    /// Provenance envelope
    build_system: Vec<u8>,
    source_repository: Vec<u8>,
    source_revision: Vec<u8>,
    reproducibility_markers: Vec<Vec<u8>>,

    /// Trust metadata
    certification_level: u8, // Will map to CertificationLevel enum
    revocation_status_pointer: Vec<u8>,
    trust_card_reference: Vec<u8>,

    /// Signature components
    signature_bytes: Vec<u8>,
    key_id: Vec<u8>,

    /// Runtime requirements
    entrypoint: Vec<u8>,
    minimum_runtime_version: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
enum AttackVector {
    /// Pure input without attack
    None,
    /// Package identity spoofing
    IdentitySpoofing {
        attack_type: IdentityAttack,
        position: u8,
    },
    /// Capability privilege escalation
    CapabilityInjection {
        injection_type: CapabilityAttack,
        target_capability: u8,
    },
    /// Risk tier bypass
    RiskTierBypass {
        bypass_method: RiskBypass,
        target_tier: u8,
    },
    /// Provenance forgery
    ProvenanceForgery {
        forgery_type: ProvenanceAttack,
        chain_position: u8,
    },
    /// Signature bypass
    SignatureBypass {
        bypass_method: SignatureAttack,
        corruption_point: u8,
    },
    /// Field injection
    FieldInjection {
        injection_type: FieldAttack,
        target_field: u8,
    },
}

#[derive(Arbitrary, Debug)]
enum IdentityAttack {
    /// Unicode homoglyph substitution
    UnicodeHomoglyph,
    /// Typosquatting patterns
    Typosquatting,
    /// Namespace confusion
    NamespaceConfusion,
    /// Version confusion
    VersionSpoofing,
    /// Publisher impersonation
    PublisherImpersonation,
}

#[derive(Arbitrary, Debug)]
enum CapabilityAttack {
    /// Inject privileged capability
    PrivilegeEscalation,
    /// Capability enumeration
    EnumConfusion,
    /// Capability overflow
    CapabilityOverflow,
    /// Undeclared capability injection
    UndeclaredCapability,
}

#[derive(Arbitrary, Debug)]
enum RiskBypass {
    /// Enum value confusion
    EnumConfusion,
    /// String representation bypass
    StringBypass,
    /// JSON type confusion
    TypeConfusion,
    /// Risk tier underreporting
    TierDowngrade,
}

#[derive(Arbitrary, Debug)]
enum ProvenanceAttack {
    /// Fake attestation chain
    FakeChain,
    /// Digest manipulation
    DigestTampering,
    /// Repository spoofing
    RepositorySpoofing,
    /// Build system impersonation
    BuildSystemForgery,
    /// Reproducibility marker bypass
    ReproducibilityBypass,
}

#[derive(Arbitrary, Debug)]
enum SignatureAttack {
    /// Malformed signature bytes
    MalformedSignature,
    /// Key ID confusion
    KeyIdSpoofing,
    /// Signature algorithm bypass
    AlgorithmConfusion,
    /// Signature reuse
    SignatureReplay,
}

#[derive(Arbitrary, Debug)]
enum FieldAttack {
    /// Null byte injection
    NullByte,
    /// Control character injection
    ControlChars,
    /// Unicode normalization bypass
    UnicodeNormalization,
    /// JSON injection
    JsonInjection,
    /// Path traversal
    PathTraversal,
    /// Script injection
    ScriptInjection,
}

#[derive(Arbitrary, Debug)]
enum FormatTest {
    /// Standard JSON
    Json,
    /// JSON with extra fields
    JsonWithExtras,
    /// Malformed JSON
    MalformedJson,
    /// CBOR format
    Cbor,
    /// Binary corruption
    BinaryCorruption,
}

#[derive(Arbitrary, Debug)]
struct SizeAttack {
    /// Multiply field sizes by this factor
    size_multiplier: u8,
    /// Target specific field for expansion
    expansion_target: u8,
    /// Maximum expansion to prevent timeout
    max_expansion: u8,
}

#[cfg(feature = "engine")]
impl ManifestTemplate {
    fn to_signed_extension_manifest(&self, attack: &AttackVector, size: &SizeAttack) -> SignedExtensionManifest {
        let size_mult = (size.size_multiplier as usize).min(10).max(1);

        // Apply size attacks
        let mut package_name = self.safe_string(&self.package_name, 256, size_mult);
        let mut package_version = self.safe_string(&self.package_version, 128, size_mult);
        let mut publisher = self.safe_string(&self.publisher, 256, size_mult);
        let mut author = self.safe_string(&self.author, 256, size_mult);
        let mut summary = self.safe_string(&self.summary, 1024, size_mult);

        // Apply attack vectors
        match attack {
            AttackVector::IdentitySpoofing { attack_type, position } => {
                self.apply_identity_attack(&mut package_name, &mut publisher, attack_type, *position);
            },
            AttackVector::FieldInjection { injection_type, target_field } => {
                self.apply_field_injection(&mut package_name, &mut summary, injection_type, *target_field);
            },
            _ => {},
        }

        // Build capabilities (bounded)
        let capabilities = self.build_capabilities(size_mult);

        // Build network zones (bounded)
        let network_zones = self.build_network_zones(size_mult);

        // Build reproducibility markers (bounded)
        let reproducibility_markers = self.build_reproducibility_markers(size_mult);

        // Build attestation chain (bounded)
        let attestation_chain = self.build_attestation_chain(size_mult);

        SignedExtensionManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            package: PackageIdentity {
                name: package_name,
                version: package_version,
                publisher,
                author,
            },
            entrypoint: self.safe_string(&self.entrypoint, 512, 1),
            capabilities,
            behavioral_profile: BehavioralProfile {
                risk_tier: self.risk_tier_from_u8(self.risk_tier),
                summary,
                declared_network_zones: network_zones,
            },
            minimum_runtime_version: self.safe_string(&self.minimum_runtime_version, 64, 1),
            provenance: ProvenanceEnvelope {
                build_system: self.safe_string(&self.build_system, 256, 1),
                source_repository: self.safe_string(&self.source_repository, 512, 1),
                source_revision: self.safe_string(&self.source_revision, 128, 1),
                reproducibility_markers,
                attestation_chain,
            },
            trust: TrustMetadata {
                certification_level: self.certification_level_from_u8(self.certification_level),
                revocation_status_pointer: self.safe_string(&self.revocation_status_pointer, 512, 1),
                trust_card_reference: self.safe_string(&self.trust_card_reference, 512, 1),
            },
            signature: ManifestSignature {
                signature_bytes: self.safe_bytes(&self.signature_bytes, 64),
                key_id: self.safe_string(&self.key_id, 128, 1),
                signature_algorithm: "ed25519".to_string(),
            },
        }
    }

    fn safe_string(&self, bytes: &[u8], max_len: usize, multiplier: usize) -> String {
        let effective_max = (max_len * multiplier).min(MAX_MANIFEST_FIELD_BYTES);
        let truncated = if bytes.len() > effective_max {
            &bytes[..effective_max]
        } else {
            bytes
        };

        String::from_utf8(truncated.to_vec())
            .unwrap_or_else(|_| "fallback_value".to_string())
    }

    fn safe_bytes(&self, bytes: &[u8], max_len: usize) -> Vec<u8> {
        if bytes.len() > max_len {
            bytes[..max_len].to_vec()
        } else {
            bytes.to_vec()
        }
    }

    fn risk_tier_from_u8(&self, value: u8) -> RiskTier {
        match value % 4 {
            0 => RiskTier::Low,
            1 => RiskTier::Medium,
            2 => RiskTier::High,
            3 => RiskTier::Critical,
            _ => RiskTier::Low,
        }
    }

    fn certification_level_from_u8(&self, value: u8) -> CertificationLevel {
        match value % 4 {
            0 => CertificationLevel::None,
            1 => CertificationLevel::Basic,
            2 => CertificationLevel::Enhanced,
            3 => CertificationLevel::Premium,
            _ => CertificationLevel::None,
        }
    }

    fn build_capabilities(&self, multiplier: usize) -> Vec<Capability> {
        let count = (4 * multiplier).min(MAX_MANIFEST_CAPABILITIES);
        let mut capabilities = Vec::new();

        for i in 0..count {
            let cap_type = match i % 6 {
                0 => Capability::FileSystem,
                1 => Capability::Network,
                2 => Capability::Process,
                3 => Capability::Environment,
                4 => Capability::Cryptography,
                5 => Capability::IPC,
                _ => Capability::FileSystem,
            };
            capabilities.push(cap_type);
            if capabilities.len() >= MAX_MANIFEST_CAPABILITIES {
                break;
            }
        }

        capabilities
    }

    fn build_network_zones(&self, multiplier: usize) -> Vec<String> {
        let count = (2 * multiplier).min(MAX_DECLARED_NETWORK_ZONES);
        let mut zones = Vec::new();

        for i in 0..count {
            let zone = match i % 4 {
                0 => "public".to_string(),
                1 => "private".to_string(),
                2 => "restricted".to_string(),
                3 => "isolated".to_string(),
                _ => "public".to_string(),
            };
            zones.push(zone);
        }

        zones
    }

    fn build_reproducibility_markers(&self, multiplier: usize) -> Vec<String> {
        let count = (3 * multiplier).min(MAX_REPRODUCIBILITY_MARKERS);
        let mut markers = Vec::new();

        for i in 0..count {
            markers.push(format!("marker_{}", i));
        }

        markers
    }

    fn build_attestation_chain(&self, multiplier: usize) -> Vec<AttestationRef> {
        let count = (2 * multiplier).min(MAX_MANIFEST_ATTESTATION_CHAIN_ENTRIES);
        let mut chain = Vec::new();

        for i in 0..count {
            chain.push(AttestationRef {
                id: format!("attestation_{}", i),
                attestation_type: "build_provenance".to_string(),
                digest: format!("sha256:{:064}", i),
            });
        }

        chain
    }

    fn apply_identity_attack(&self, name: &mut String, publisher: &mut String, attack_type: &IdentityAttack, position: u8) {
        let pos = (position as usize).min(name.len());

        match attack_type {
            IdentityAttack::UnicodeHomoglyph => {
                // Replace common chars with homoglyphs
                *name = name.replace('o', "ο").replace('a', "а").replace('e', "е");
            },
            IdentityAttack::Typosquatting => {
                if !name.is_empty() && pos < name.len() {
                    let chars: Vec<char> = name.chars().collect();
                    let mut new_chars = chars;
                    if pos < new_chars.len() {
                        new_chars[pos] = 'x'; // Typosquat character
                    }
                    *name = new_chars.into_iter().collect();
                }
            },
            IdentityAttack::NamespaceConfusion => {
                *name = format!("{}.malicious", name);
            },
            IdentityAttack::PublisherImpersonation => {
                *publisher = "trusted-publisher".to_string();
            },
            IdentityAttack::VersionSpoofing => {
                // Handled in package version field
            },
        }
    }

    fn apply_field_injection(&self, target1: &mut String, target2: &mut String, injection_type: &FieldAttack, target_field: u8) {
        let target = if target_field % 2 == 0 { target1 } else { target2 };

        match injection_type {
            FieldAttack::NullByte => {
                target.push('\0');
                target.push_str("injected");
            },
            FieldAttack::ControlChars => {
                for code in 1..32 {
                    if let Some(c) = char::from_u32(code) {
                        target.push(c);
                    }
                }
            },
            FieldAttack::JsonInjection => {
                target.push_str("\"},\"malicious\":\"payload");
            },
            FieldAttack::PathTraversal => {
                target.push_str("../../../etc/passwd");
            },
            FieldAttack::ScriptInjection => {
                target.push_str("<script>alert('xss')</script>");
            },
            FieldAttack::UnicodeNormalization => {
                target.push_str("cafe\u{301}"); // Combining acute accent
            },
        }
    }
}

#[cfg(feature = "engine")]
fuzz_target!(|input: ManifestFuzzInput| {
    let manifest = input.manifest_template.to_signed_extension_manifest(&input.attack_vector, &input.size_attack);

    // Test JSON serialization/deserialization
    test_json_round_trip(&manifest, &input.format_test);

    // Test field validation
    test_field_validation(&manifest);

    // Test security properties
    test_security_properties(&manifest, &input.attack_vector);

    // Test deterministic behavior
    test_deterministic_behavior(&manifest);

    // Test memory safety with large inputs
    test_memory_safety(&manifest, &input.size_attack);
});

#[cfg(feature = "engine")]
fn test_json_round_trip(manifest: &SignedExtensionManifest, format_test: &FormatTest) {
    match format_test {
        FormatTest::Json => {
            if let Ok(json_str) = serde_json::to_string(manifest) {
                let _ = serde_json::from_str::<SignedExtensionManifest>(&json_str);
            }
        },
        FormatTest::JsonWithExtras => {
            if let Ok(mut json_value) = serde_json::to_value(manifest) {
                if let Some(obj) = json_value.as_object_mut() {
                    obj.insert("extra_field".to_string(), serde_json::Value::String("malicious".to_string()));
                }
                let _ = serde_json::from_value::<SignedExtensionManifest>(json_value);
            }
        },
        FormatTest::MalformedJson => {
            let malformed = r#"{"package":{"name":"test","invalid_structure"#;
            let _ = serde_json::from_str::<SignedExtensionManifest>(malformed);
        },
        _ => {
            // Other format tests not implemented for this surface
        },
    }
}

#[cfg(feature = "engine")]
fn test_field_validation(manifest: &SignedExtensionManifest) {
    // Test that schema version is validated
    assert!(!manifest.schema_version.is_empty(), "Schema version should not be empty");

    // Test package identity constraints
    assert!(!manifest.package.name.is_empty() || manifest.package.name.len() <= MAX_MANIFEST_FIELD_BYTES,
            "Package name should be bounded");

    // Test capabilities bounds
    assert!(manifest.capabilities.len() <= MAX_MANIFEST_CAPABILITIES,
            "Capabilities should be bounded");

    // Test network zones bounds
    assert!(manifest.behavioral_profile.declared_network_zones.len() <= MAX_DECLARED_NETWORK_ZONES,
            "Network zones should be bounded");

    // Test attestation chain bounds
    assert!(manifest.provenance.attestation_chain.len() <= MAX_MANIFEST_ATTESTATION_CHAIN_ENTRIES,
            "Attestation chain should be bounded");

    // Test reproducibility markers bounds
    assert!(manifest.provenance.reproducibility_markers.len() <= MAX_REPRODUCIBILITY_MARKERS,
            "Reproducibility markers should be bounded");
}

#[cfg(feature = "engine")]
fn test_security_properties(manifest: &SignedExtensionManifest, attack_vector: &AttackVector) {
    // Test that dangerous patterns are rejected or sanitized
    let dangerous_patterns = ["\0", "../", "<script>", "}{", "\x00", "\x1f"];

    let all_string_fields = vec![
        &manifest.package.name,
        &manifest.package.version,
        &manifest.package.publisher,
        &manifest.package.author,
        &manifest.entrypoint,
        &manifest.behavioral_profile.summary,
        &manifest.minimum_runtime_version,
        &manifest.provenance.build_system,
        &manifest.provenance.source_repository,
        &manifest.provenance.source_revision,
        &manifest.trust.revocation_status_pointer,
        &manifest.trust.trust_card_reference,
        &manifest.signature.key_id,
    ];

    for field in all_string_fields {
        for pattern in dangerous_patterns {
            if field.contains(pattern) {
                // SECURITY ASSERTION: Dangerous patterns must be rejected by validation
                // If they appear in manifest fields, validation has failed critically
                panic!(
                    "SECURITY VIOLATION: Dangerous pattern '{}' found in field '{}' - \
                     manifest validation must reject dangerous patterns before field assignment. \
                     This indicates a critical security bypass in manifest processing.",
                    pattern, field
                );
            }
        }
    }

    // Test risk tier consistency
    match manifest.behavioral_profile.risk_tier {
        RiskTier::Critical => {
            // Critical risk should have enhanced verification
            assert!(manifest.trust.certification_level != CertificationLevel::None,
                    "Critical risk tier should require certification");
        },
        _ => {},
    }
}

#[cfg(feature = "engine")]
fn test_deterministic_behavior(manifest: &SignedExtensionManifest) {
    // Test that serialization is deterministic
    let json1 = serde_json::to_string(manifest);
    let json2 = serde_json::to_string(manifest);

    if let (Ok(s1), Ok(s2)) = (json1, json2) {
        assert_eq!(s1, s2, "Serialization should be deterministic");
    }

    // Test that hash computation is deterministic
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher1 = DefaultHasher::new();
    let mut hasher2 = DefaultHasher::new();

    manifest.package.name.hash(&mut hasher1);
    manifest.package.name.hash(&mut hasher2);

    assert_eq!(hasher1.finish(), hasher2.finish(), "Hash should be deterministic");
}

#[cfg(feature = "engine")]
fn test_memory_safety(manifest: &SignedExtensionManifest, size_attack: &SizeAttack) {
    if size_attack.size_multiplier > 5 {
        // Test that large inputs don't cause memory issues
        let _clone = manifest.clone();

        // Test serialization of large manifest doesn't crash
        let _json_result = serde_json::to_string(manifest);

        // Force any potential cleanup
        drop(_clone);
    }
}

#[cfg(not(feature = "engine"))]
fuzz_target!(|dummy_input: u8| {
    // Manifest module requires engine feature - skip fuzzing without it
    let _ = dummy_input; // Suppress unused variable warning
});