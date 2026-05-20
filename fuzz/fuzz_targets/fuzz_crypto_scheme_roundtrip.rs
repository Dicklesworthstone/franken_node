#![no_main]

use arbitrary::Arbitrary;
use ed25519_dalek::SigningKey;
use frankenengine_node::crypto::{Ed25519Scheme, SignatureScheme};
use libfuzzer_sys::fuzz_target;

const MAX_DOMAIN_BYTES: usize = 256;
const MAX_MESSAGE_BYTES: usize = 4096;

#[derive(Debug, Arbitrary)]
struct CryptoSchemeRoundtripCase {
    seed: [u8; 32],
    domain: Vec<u8>,
    message: Vec<u8>,
}

fuzz_target!(|case: CryptoSchemeRoundtripCase| {
    let domain = bounded(case.domain, MAX_DOMAIN_BYTES);
    let message = bounded(case.message, MAX_MESSAGE_BYTES);
    let signing_key = SigningKey::from_bytes(&case.seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let signature = Ed25519Scheme::sign_with_domain(&case.seed, &domain, &message)
        .expect("32-byte Ed25519 seed should sign");

    assert!(Ed25519Scheme::verify_with_domain(
        &public_key,
        &domain,
        &message,
        &signature
    ));
});

fn bounded(mut bytes: Vec<u8>, max: usize) -> Vec<u8> {
    if bytes.len() > max {
        bytes.truncate(max);
    }
    bytes
}
