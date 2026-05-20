#![no_main]

use arbitrary::Arbitrary;
use ed25519_dalek::SigningKey;
use frankenengine_node::crypto::{CryptoSigner, Ed25519Scheme, Ed25519Signer};
use libfuzzer_sys::fuzz_target;

const MAX_CONTEXT_BYTES: usize = 128;
const MAX_MESSAGE_BYTES: usize = 2048;
const MAX_CHAIN_LEN: usize = 8;

#[derive(Debug, Arbitrary)]
struct CryptoSignerChainCase {
    seed: [u8; 32],
    steps: Vec<CryptoSignerChainStep>,
}

#[derive(Debug, Arbitrary)]
struct CryptoSignerChainStep {
    context: Vec<u8>,
    message: Vec<u8>,
}

fuzz_target!(|case: CryptoSignerChainCase| {
    let signer = Ed25519Signer::new();
    let signing_key = SigningKey::from_bytes(&case.seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let mut prior: Vec<(String, Vec<u8>, [u8; 64])> = Vec::new();

    for step in case.steps.into_iter().take(MAX_CHAIN_LEN) {
        let context = context_string(step.context);
        let message = bounded(step.message, MAX_MESSAGE_BYTES);
        let signature = signer
            .sign_message(&case.seed, &context, &message)
            .expect("32-byte Ed25519 seed should sign");
        let fresh_signature = Ed25519Signer::new()
            .sign_message(&case.seed, &context, &message)
            .expect("fresh signer should produce the same deterministic signature");
        assert_eq!(signature, fresh_signature);

        let domain = format!("franken_node_{context}:");
        assert!(Ed25519Scheme::verify_with_domain(
            &public_key,
            domain.as_bytes(),
            &message,
            &signature
        ));

        for (old_context, old_message, old_signature) in &prior {
            if old_context == &context && old_message == &message {
                continue;
            }
            assert!(!Ed25519Scheme::verify_with_domain(
                &public_key,
                domain.as_bytes(),
                &message,
                old_signature
            ));
        }

        prior.push((context, message, signature));
    }
});

fn bounded(mut bytes: Vec<u8>, max: usize) -> Vec<u8> {
    if bytes.len() > max {
        bytes.truncate(max);
    }
    bytes
}

fn context_string(bytes: Vec<u8>) -> String {
    let bounded = bounded(bytes, MAX_CONTEXT_BYTES);
    if bounded.is_empty() {
        "fuzz_empty".to_string()
    } else {
        hex::encode(bounded)
    }
}
