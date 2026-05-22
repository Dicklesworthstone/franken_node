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
    split_selector: u8,
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

    let raw_sig =
        Ed25519Scheme::sign_raw(&case.seed, &message).expect("32-byte Ed25519 seed should sign");
    assert!(Ed25519Scheme::verify_raw(
        &public_key,
        &message,
        &raw_sig
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        &public_key,
        &domain_a,
        &message,
        &raw_sig
    ));
    assert!(!Ed25519Scheme::verify_raw(
        &public_key,
        &message,
        &sig_a
    ));

    assert_length_prefixed_split_resistance(
        &case.seed,
        &public_key,
        case.split_selector,
        &domain_a,
        &message,
    );
});

fn bounded(mut bytes: Vec<u8>, max: usize) -> Vec<u8> {
    if bytes.len() > max {
        bytes.truncate(max);
    }
    bytes
}

fn assert_length_prefixed_split_resistance(
    seed: &[u8; 32],
    public_key: &[u8; 32],
    split_selector: u8,
    domain: &[u8],
    message: &[u8],
) {
    let mut joined = Vec::with_capacity(domain.len() + message.len());
    joined.extend_from_slice(domain);
    joined.extend_from_slice(message);
    if joined.len() < 2 {
        return;
    }

    let split_a = 1 + usize::from(split_selector) % (joined.len() - 1);
    let split_b = if split_a == joined.len() - 1 {
        0
    } else {
        split_a + 1
    };
    let (domain_a, message_a) = joined.split_at(split_a);
    let (domain_b, message_b) = joined.split_at(split_b);

    let sig_a = Ed25519Scheme::sign_with_domain(seed, domain_a, message_a)
        .expect("32-byte Ed25519 seed should sign");
    let sig_b = Ed25519Scheme::sign_with_domain(seed, domain_b, message_b)
        .expect("32-byte Ed25519 seed should sign");

    assert_ne!(sig_a, sig_b);
    assert!(Ed25519Scheme::verify_with_domain(
        public_key, domain_a, message_a, &sig_a
    ));
    assert!(Ed25519Scheme::verify_with_domain(
        public_key, domain_b, message_b, &sig_b
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        public_key, domain_a, message_a, &sig_b
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        public_key, domain_b, message_b, &sig_a
    ));
}
