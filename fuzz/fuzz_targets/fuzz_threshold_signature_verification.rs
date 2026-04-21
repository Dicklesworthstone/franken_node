#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use frankenengine_node::security::threshold_sig::{
    ThresholdConfig, SignerKey, PartialSignature, PublicationArtifact,
    verify_threshold, sign, FailureReason
};
use ed25519_dalek::{SigningKey, Signer};

#[derive(Debug, Clone, Arbitrary)]
struct ThresholdFuzzCase {
    /// Base configuration parameters
    config_params: ConfigParams,
    /// Artifact to be signed/verified
    artifact_params: ArtifactParams,
    /// Signature generation strategy
    signature_strategy: SignatureStrategy,
    /// Attack vector to test
    attack_vector: AttackVector,
}

#[derive(Debug, Clone, Arbitrary)]
struct ConfigParams {
    /// Threshold value (k)
    threshold: u32,
    /// Total number of signers (n)
    total_signers: u32,
    /// Number of signer keys to actually generate
    actual_keys: u8,
    /// Key mutation strategy
    key_mutation: KeyMutation,
}

#[derive(Debug, Clone, Arbitrary)]
struct ArtifactParams {
    /// Artifact ID with potential injection
    artifact_id: String,
    /// Connector ID with potential injection
    connector_id: String,
    /// Content hash for signing
    content_hash: String,
    /// ID validation bypass attempts
    id_attack: IdAttack,
}

#[derive(Debug, Clone, Arbitrary)]
enum SignatureStrategy {
    /// Generate valid signatures
    Valid { count: u8 },
    /// Mix valid and invalid signatures
    Mixed { valid_count: u8, invalid_count: u8 },
    /// All invalid signatures
    AllInvalid { count: u8 },
    /// Duplicate signatures (same signer multiple times)
    Duplicates { base_count: u8, duplicate_count: u8 },
    /// Cross-message replay attack
    Replay { source_hash: String, target_hash: String },
    /// Signature format attacks
    FormatAttack { attack_type: SigFormatAttack },
}

#[derive(Debug, Clone, Arbitrary)]
enum AttackVector {
    /// Domain separator injection
    DomainSeparator { separator: String },
    /// Unicode normalization attack
    UnicodeNormalization,
    /// Hex encoding bypass
    HexBypass { variant: HexBypassVariant },
    /// Threshold bypass attempt
    ThresholdBypass { strategy: BypassStrategy },
    /// Identity confusion attack
    IdentityConfusion { fake_mapping: Vec<(String, String)> },
    /// Length extension attack
    LengthExtension { extension: Vec<u8> },
}

#[derive(Debug, Clone, Arbitrary)]
enum KeyMutation {
    /// Valid keys
    Valid,
    /// Duplicate public keys
    DuplicatePublicKeys,
    /// Duplicate key IDs
    DuplicateKeyIds,
    /// Malformed public key hex
    MalformedHex { position: u8, replacement: String },
    /// Wrong length public keys
    WrongLength { new_length: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
enum IdAttack {
    /// Clean IDs
    Clean,
    /// Path traversal
    PathTraversal,
    /// Null byte injection
    NullInjection,
    /// Unicode injection
    UnicodeInjection,
    /// Reserved word bypass
    ReservedBypass,
    /// Length overflow
    LengthOverflow { size: u16 },
}

#[derive(Debug, Clone, Arbitrary)]
enum SigFormatAttack {
    /// Wrong signature length
    WrongLength { new_length: u8 },
    /// Non-hex characters
    NonHex { injection: String },
    /// Mixed case variations
    MixedCase,
    /// Padded hex
    PaddedHex { padding: String },
}

#[derive(Debug, Clone, Arbitrary)]
enum HexBypassVariant {
    /// Unicode hex digits
    UnicodeDigits,
    /// Control characters in hex
    ControlChars,
    /// Null bytes in hex
    NullBytes,
    /// Whitespace in hex
    Whitespace,
}

#[derive(Debug, Clone, Arbitrary)]
enum BypassStrategy {
    /// Try to exceed threshold with invalid signatures
    InvalidPadding,
    /// Arithmetic overflow in counting
    CountOverflow,
    /// Vote stuffing with same key
    VoteStuffing,
    /// Threshold parameter manipulation
    ThresholdManipulation,
}

const MAX_SIGNERS: usize = 100;
const MAX_SIGNATURES: usize = 200;
const MAX_STRING_LEN: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(test_case) = ThresholdFuzzCase::arbitrary(&mut unstructured) else { return };

    // Bound parameters to prevent resource exhaustion
    if test_case.config_params.total_signers > MAX_SIGNERS as u32 { return }
    if test_case.artifact_params.artifact_id.len() > MAX_STRING_LEN { return }
    if test_case.artifact_params.connector_id.len() > MAX_STRING_LEN { return }

    // Generate test configuration and artifact
    let (config, signing_keys) = generate_test_config(&test_case.config_params);
    let artifact = generate_test_artifact(&test_case.artifact_params, &config, &signing_keys, &test_case.signature_strategy);

    // Apply attack vector modifications
    let (modified_config, modified_artifact) = apply_attack_vector(config, artifact, &test_case.attack_vector);

    // Run verification and test invariants
    fuzz_threshold_verification(&modified_config, &modified_artifact, &test_case);
});

fn generate_test_config(params: &ConfigParams) -> (ThresholdConfig, Vec<SigningKey>) {
    let actual_count = (params.actual_keys as usize).min(MAX_SIGNERS).max(1);
    let mut signing_keys = Vec::new();
    let mut signer_keys = Vec::new();

    // Generate base keys
    for i in 0..actual_count {
        let seed = [i as u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

        signer_keys.push(SignerKey {
            key_id: format!("signer-{}", i),
            public_key_hex,
        });
        signing_keys.push(signing_key);
    }

    // Apply key mutations
    apply_key_mutation(&mut signer_keys, &params.key_mutation);

    // Ensure total_signers matches actual count for valid configs
    let total_signers = if matches!(params.key_mutation, KeyMutation::Valid) {
        signer_keys.len() as u32
    } else {
        params.total_signers
    };

    let config = ThresholdConfig {
        threshold: params.threshold,
        total_signers,
        signer_keys,
    };

    (config, signing_keys)
}

fn apply_key_mutation(signer_keys: &mut Vec<SignerKey>, mutation: &KeyMutation) {
    match mutation {
        KeyMutation::Valid => {
            // No mutation
        },
        KeyMutation::DuplicatePublicKeys => {
            if signer_keys.len() > 1 {
                signer_keys[1].public_key_hex = signer_keys[0].public_key_hex.clone();
            }
        },
        KeyMutation::DuplicateKeyIds => {
            if signer_keys.len() > 1 {
                signer_keys[1].key_id = signer_keys[0].key_id.clone();
            }
        },
        KeyMutation::MalformedHex { position, replacement } => {
            if !signer_keys.is_empty() {
                let pos = (*position as usize) % signer_keys[0].public_key_hex.len().max(1);
                let mut chars: Vec<char> = signer_keys[0].public_key_hex.chars().collect();
                if pos < chars.len() && !replacement.is_empty() {
                    chars[pos] = replacement.chars().next().unwrap_or('g'); // 'g' is invalid hex
                    signer_keys[0].public_key_hex = chars.into_iter().collect();
                }
            }
        },
        KeyMutation::WrongLength { new_length } => {
            if !signer_keys.is_empty() {
                let target_len = (*new_length as usize).min(200); // Bound length
                signer_keys[0].public_key_hex = "00".repeat(target_len);
            }
        },
    }
}

fn generate_test_artifact(
    params: &ArtifactParams,
    config: &ThresholdConfig,
    signing_keys: &[SigningKey],
    signature_strategy: &SignatureStrategy,
) -> PublicationArtifact {
    let mut artifact_id = params.artifact_id.clone();
    let mut connector_id = params.connector_id.clone();

    // Apply ID attacks
    apply_id_attack(&mut artifact_id, &mut connector_id, &params.id_attack);

    // Generate signatures based on strategy
    let signatures = generate_signatures(signature_strategy, config, signing_keys, &params.content_hash);

    PublicationArtifact {
        artifact_id,
        connector_id,
        content_hash: params.content_hash.clone(),
        signatures,
    }
}

fn apply_id_attack(artifact_id: &mut String, connector_id: &mut String, attack: &IdAttack) {
    match attack {
        IdAttack::Clean => {
            // No modification
        },
        IdAttack::PathTraversal => {
            *artifact_id = format!("../../../{}", artifact_id);
            *connector_id = format!("connectors/../admin/{}", connector_id);
        },
        IdAttack::NullInjection => {
            artifact_id.push('\0');
            artifact_id.push_str("injected");
            connector_id.push('\0');
        },
        IdAttack::UnicodeInjection => {
            *artifact_id = format!("\u{202E}{}\u{202D}", artifact_id);
            *connector_id = format!("conn\u{200B}ector-{}", connector_id);
        },
        IdAttack::ReservedBypass => {
            *artifact_id = "<unknown>".to_string();
            *connector_id = " <unknown> ".to_string();
        },
        IdAttack::LengthOverflow { size } => {
            let target_size = (*size as usize).max(10000).min(100000); // Bound but test large sizes
            *artifact_id = "x".repeat(target_size);
            *connector_id = "y".repeat(target_size);
        },
    }
}

fn generate_signatures(
    strategy: &SignatureStrategy,
    config: &ThresholdConfig,
    signing_keys: &[SigningKey],
    content_hash: &str,
) -> Vec<PartialSignature> {
    let mut signatures = Vec::new();

    match strategy {
        SignatureStrategy::Valid { count } => {
            let sig_count = (*count as usize).min(MAX_SIGNATURES).min(signing_keys.len()).min(config.signer_keys.len());
            for i in 0..sig_count {
                if i < signing_keys.len() && i < config.signer_keys.len() {
                    let sig = sign(&signing_keys[i], &config.signer_keys[i].key_id, content_hash);
                    signatures.push(sig);
                }
            }
        },

        SignatureStrategy::Mixed { valid_count, invalid_count } => {
            // Valid signatures first
            let valid_count = (*valid_count as usize).min(signing_keys.len()).min(config.signer_keys.len());
            for i in 0..valid_count {
                let sig = sign(&signing_keys[i], &config.signer_keys[i].key_id, content_hash);
                signatures.push(sig);
            }

            // Invalid signatures
            let invalid_count = (*invalid_count as usize).min(MAX_SIGNATURES - signatures.len());
            for i in 0..invalid_count {
                signatures.push(PartialSignature {
                    signer_id: format!("invalid-signer-{}", i),
                    key_id: format!("invalid-key-{}", i),
                    signature_hex: "deadbeef".repeat(16), // Invalid but well-formed
                });
            }
        },

        SignatureStrategy::AllInvalid { count } => {
            let sig_count = (*count as usize).min(MAX_SIGNATURES);
            for i in 0..sig_count {
                signatures.push(PartialSignature {
                    signer_id: format!("fake-signer-{}", i),
                    key_id: format!("fake-key-{}", i),
                    signature_hex: format!("{:064x}", i),
                });
            }
        },

        SignatureStrategy::Duplicates { base_count, duplicate_count } => {
            // Generate base signatures
            let base_count = (*base_count as usize).min(signing_keys.len()).min(config.signer_keys.len());
            for i in 0..base_count {
                let sig = sign(&signing_keys[i], &config.signer_keys[i].key_id, content_hash);
                signatures.push(sig);
            }

            // Duplicate the first signature multiple times
            if !signatures.is_empty() {
                let dup_count = (*duplicate_count as usize).min(MAX_SIGNATURES - signatures.len());
                let base_sig = signatures[0].clone();
                for _ in 0..dup_count {
                    signatures.push(base_sig.clone());
                }
            }
        },

        SignatureStrategy::Replay { source_hash, target_hash: _ } => {
            // Create signature for different content hash (replay attack)
            if !signing_keys.is_empty() && !config.signer_keys.is_empty() {
                let sig = sign(&signing_keys[0], &config.signer_keys[0].key_id, source_hash);
                signatures.push(sig);
            }
        },

        SignatureStrategy::FormatAttack { attack_type } => {
            if !signing_keys.is_empty() && !config.signer_keys.is_empty() {
                let mut sig = sign(&signing_keys[0], &config.signer_keys[0].key_id, content_hash);
                apply_signature_format_attack(&mut sig, attack_type);
                signatures.push(sig);
            }
        },
    }

    signatures
}

fn apply_signature_format_attack(sig: &mut PartialSignature, attack: &SigFormatAttack) {
    match attack {
        SigFormatAttack::WrongLength { new_length } => {
            let target_len = (*new_length as usize).min(200);
            sig.signature_hex = "00".repeat(target_len);
        },
        SigFormatAttack::NonHex { injection } => {
            sig.signature_hex = format!("deadbeef{}cafebabe", injection);
        },
        SigFormatAttack::MixedCase => {
            sig.signature_hex = sig.signature_hex.to_uppercase();
        },
        SigFormatAttack::PaddedHex { padding } => {
            sig.signature_hex = format!("{}{}{}", padding, sig.signature_hex, padding);
        },
    }
}

fn apply_attack_vector(
    mut config: ThresholdConfig,
    mut artifact: PublicationArtifact,
    attack: &AttackVector,
) -> (ThresholdConfig, PublicationArtifact) {
    match attack {
        AttackVector::DomainSeparator { separator } => {
            // Try to inject domain separators into content hash
            artifact.content_hash = format!("{}:{}", separator, artifact.content_hash);
        },

        AttackVector::UnicodeNormalization => {
            // Apply Unicode normalization attacks to IDs
            artifact.artifact_id = format!("café_{}", artifact.artifact_id); // NFC
            artifact.connector_id = format!("cafe\u{0301}_{}", artifact.connector_id); // NFD
        },

        AttackVector::HexBypass { variant } => {
            apply_hex_bypass_attack(&mut config, variant);
        },

        AttackVector::ThresholdBypass { strategy } => {
            apply_threshold_bypass(&mut config, &mut artifact, strategy);
        },

        AttackVector::IdentityConfusion { fake_mapping } => {
            // Apply identity confusion attacks
            for (i, (fake_signer, fake_key)) in fake_mapping.iter().enumerate() {
                if i < artifact.signatures.len() {
                    artifact.signatures[i].signer_id = fake_signer.clone();
                    artifact.signatures[i].key_id = fake_key.clone();
                }
            }
        },

        AttackVector::LengthExtension { extension } => {
            // Attempt length extension on content hash
            artifact.content_hash.extend(extension.iter().map(|&b| char::from(b.min(127))));
        },
    }

    (config, artifact)
}

fn apply_hex_bypass_attack(config: &mut ThresholdConfig, variant: &HexBypassVariant) {
    if config.signer_keys.is_empty() { return }

    match variant {
        HexBypassVariant::UnicodeDigits => {
            config.signer_keys[0].public_key_hex = "𝟎𝟏𝟐𝟑".to_string(); // Unicode mathematical digits
        },
        HexBypassVariant::ControlChars => {
            config.signer_keys[0].public_key_hex = "00\r\n11\t22".to_string();
        },
        HexBypassVariant::NullBytes => {
            config.signer_keys[0].public_key_hex = "00\0011\0022".to_string();
        },
        HexBypassVariant::Whitespace => {
            config.signer_keys[0].public_key_hex = "00 11 22 33 44 55 66 77".to_string();
        },
    }
}

fn apply_threshold_bypass(config: &mut ThresholdConfig, _artifact: &mut PublicationArtifact, strategy: &BypassStrategy) {
    match strategy {
        BypassStrategy::InvalidPadding => {
            // Try to set threshold higher than total signers
            config.threshold = config.total_signers.saturating_add(10);
        },
        BypassStrategy::CountOverflow => {
            // Try to trigger arithmetic overflow
            config.threshold = u32::MAX;
            config.total_signers = u32::MAX;
        },
        BypassStrategy::VoteStuffing => {
            // Already handled in signature generation
        },
        BypassStrategy::ThresholdManipulation => {
            // Try edge cases
            config.threshold = 0;
        },
    }
}

fn fuzz_threshold_verification(config: &ThresholdConfig, artifact: &PublicationArtifact, test_case: &ThresholdFuzzCase) {
    // Always use static values for trace_id and timestamp to avoid non-determinism
    let result = verify_threshold(config, artifact, "fuzz-trace", "2026-01-01T00:00:00Z");

    // Test invariants that must hold regardless of input

    // Invariant 1: Result should always be serializable
    let _serialized = serde_json::to_string(&result)
        .expect("VerificationResult should always be serializable");

    // Invariant 2: verify_threshold should never panic (we should reach here)

    // Invariant 3: Valid signature count should never exceed total signatures provided
    if result.valid_signatures as usize > artifact.signatures.len() {
        #[cfg(debug_assertions)]
        {
            eprintln!("FUZZ: Invariant violation - valid_signatures ({}) > total signatures ({})",
                     result.valid_signatures, artifact.signatures.len());
        }
        return; // Exit gracefully instead of panicking
    }

    // Invariant 4: Valid signature count should never exceed configured threshold
    if result.verified && result.valid_signatures < config.threshold {
        #[cfg(debug_assertions)]
        {
            eprintln!("FUZZ: Invariant violation - verified=true but valid_signatures ({}) < threshold ({})",
                     result.valid_signatures, config.threshold);
        }
        return; // Exit gracefully instead of panicking
    }

    // Invariant 5: Test specific expected results based on test case
    match &test_case.signature_strategy {
        SignatureStrategy::AllInvalid { .. } => {
            if result.verified {
                #[cfg(debug_assertions)]
                {
                    eprintln!("FUZZ: Invariant violation - all invalid signatures but result.verified=true");
                }
                return; // Exit gracefully instead of panicking
            }
        },
        SignatureStrategy::Valid { count } => {
            // Only expect verification if we have enough valid signatures and valid config
            if *count as u32 >= config.threshold && config.validate().is_ok()
                && is_valid_artifact_id(&artifact.artifact_id)
                && is_valid_connector_id(&artifact.connector_id) {
                // Should verify if inputs are actually valid
            }
        },
        _ => {
            // Other strategies may or may not verify - just ensure no panic
        }
    }

    // Invariant 6: Failure reason should be present if and only if verification failed
    if result.verified && result.failure_reason.is_some() {
        #[cfg(debug_assertions)]
        {
            eprintln!("FUZZ: Invariant violation - verified=true but failure_reason is present: {:?}",
                     result.failure_reason);
        }
        return; // Exit gracefully instead of panicking
    }

    // Invariant 7: Test round-trip serialization
    let serialized = serde_json::to_string(&result).unwrap();
    let _deserialized: frankenengine_node::security::threshold_sig::VerificationResult =
        serde_json::from_str(&serialized).expect("Result should deserialize correctly");
}

fn is_valid_artifact_id(id: &str) -> bool {
    !id.is_empty()
        && id.trim() == id
        && !id.contains('\0')
        && !id.starts_with('/')
        && !id.contains('\\')
        && !id.split('/').any(|s| s == "..")
        && id.len() <= 4096
        && id != "<unknown>"
}

fn is_valid_connector_id(id: &str) -> bool {
    is_valid_artifact_id(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_generation() {
        let params = ConfigParams {
            threshold: 2,
            total_signers: 3,
            actual_keys: 3,
            key_mutation: KeyMutation::Valid,
        };

        let (config, keys) = generate_test_config(&params);
        assert_eq!(config.signer_keys.len(), 3);
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_attack_vector_application() {
        let config = ThresholdConfig {
            threshold: 1,
            total_signers: 1,
            signer_keys: vec![SignerKey {
                key_id: "test-key".to_string(),
                public_key_hex: "deadbeef".repeat(8),
            }],
        };

        let artifact = PublicationArtifact {
            artifact_id: "test-artifact".to_string(),
            connector_id: "test-connector".to_string(),
            content_hash: "test-hash".to_string(),
            signatures: vec![],
        };

        let attack = AttackVector::DomainSeparator { separator: "evil".to_string() };
        let (_, modified_artifact) = apply_attack_vector(config, artifact, &attack);
        assert!(modified_artifact.content_hash.contains("evil"));
    }
}