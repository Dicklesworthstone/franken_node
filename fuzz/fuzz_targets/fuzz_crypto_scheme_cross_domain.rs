#![no_main]

use arbitrary::Arbitrary;
use ed25519_dalek::SigningKey;
use frankenengine_node::crypto::{Ed25519Scheme, SignatureScheme};
use libfuzzer_sys::fuzz_target;

const MAX_DOMAIN_BYTES: usize = 256;
const MAX_MESSAGE_BYTES: usize = 4096;

#[derive(Debug, Arbitrary)]
struct CryptoSchemeCrossDomainCase {
    seed: [u8; 32],
    domain_a: Vec<u8>,
    domain_b: Vec<u8>,
    message: Vec<u8>,
}

fuzz_target!(|case: CryptoSchemeCrossDomainCase| {
    let domain_a = bounded(case.domain_a, MAX_DOMAIN_BYTES);
    let mut domain_b = bounded(case.domain_b, MAX_DOMAIN_BYTES);
    if domain_a == domain_b {
        domain_b.push(0xFF);
    }
    let message = bounded(case.message, MAX_MESSAGE_BYTES);
    let signing_key = SigningKey::from_bytes(&case.seed);
    let public_key = signing_key.verifying_key().to_bytes();

    let sig_a = Ed25519Scheme::sign_with_domain(&case.seed, &domain_a, &message)
        .expect("32-byte Ed25519 seed should sign");
    let sig_b = Ed25519Scheme::sign_with_domain(&case.seed, &domain_b, &message)
        .expect("32-byte Ed25519 seed should sign");

    assert_ne!(sig_a, sig_b);
    assert!(Ed25519Scheme::verify_with_domain(
        &public_key,
        &domain_a,
        &message,
        &sig_a
    ));
    assert!(Ed25519Scheme::verify_with_domain(
        &public_key,
        &domain_b,
        &message,
        &sig_b
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        &public_key,
        &domain_a,
        &message,
        &sig_b
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        &public_key,
        &domain_b,
        &message,
        &sig_a
    ));
});

fn bounded(mut bytes: Vec<u8>, max: usize) -> Vec<u8> {
    if bytes.len() > max {
        bytes.truncate(max);
    }
    bytes
}
