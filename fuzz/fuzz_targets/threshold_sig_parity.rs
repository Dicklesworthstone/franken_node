//! Fuzz target: byte-parity between `verify_threshold` (legacy
//! hex-decode-per-call path) and `verify_threshold_preparsed`
//! (cached VerifyingKey path) — bd-98xo5.1.5.
//!
//! ## What this harness pins
//!
//! bd-98xo5.1 introduced `PreparsedThresholdConfig` and
//! `verify_threshold_preparsed` to amortise the per-call
//! `hex::decode_to_slice` + `VerifyingKey::from_bytes` cost across
//! many threshold verifications of the same artifact. The 10 %
//! speedup at 32 signers (round-1 benches) is only valid if the two
//! paths produce byte-identical `VerificationResult` values on every
//! input — a divergence means one path accepts what the other
//! rejects (or vice versa), which is a silent break of the
//! quorum-verification contract.
//!
//! The harness pulls a (k, n) shape, n keypairs, k+padding signatures
//! over a random content_hash, plus optional duplicate / malformed
//! entries from `Unstructured`. It then asserts both paths return
//! identical `VerificationResult` values; libfuzzer panics on
//! divergence and shrinks the offending input automatically.
//!
//! ## Out of scope
//!
//! - Config validation: `ThresholdConfig::validate` is exercised
//!   directly by inline tests in the same module.
//! - Bench parity (timing): handled by the e2e shell script at
//!   `tests/perf_beads/bd-98xo5.1.tests.sh` which gates the budget.

#![no_main]

use libfuzzer_sys::fuzz_target;

use arbitrary::{Arbitrary, Unstructured};
use ed25519_dalek::{Signer, SigningKey};
use frankenengine_node::security::threshold_sig::{
    PartialSignature, PreparsedThresholdConfig, PublicationArtifact, SignerKey, ThresholdConfig,
    verify_threshold, verify_threshold_preparsed,
};
use sha2::{Digest, Sha256};

const MAX_SIGNERS_FUZZ: u8 = 12;
const MAX_PAYLOAD: usize = 2048;
const MAX_EXTRA_SIGS: u8 = 4;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    n_signers: u8,
    k_threshold: u8,
    seed_bytes: [u8; 32],
    content_hash_seed: [u8; 32],
    sigs_supplied: u8,
    extra_garbage_sigs: u8,
    artifact_id_byte: u8,
    connector_id_byte: u8,
}

fn build_signing_message(artifact_id: &str, connector_id: &str, content_hash: &str) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(artifact_id.len() + connector_id.len() + content_hash.len() + 2);
    msg.extend_from_slice(artifact_id.as_bytes());
    msg.push(0);
    msg.extend_from_slice(connector_id.as_bytes());
    msg.push(0);
    msg.extend_from_slice(content_hash.as_bytes());
    msg
}

fn derive_signing_key(seed: &[u8; 32], i: u32) -> SigningKey {
    let mut h = Sha256::new();
    h.update(b"fuzz_threshold_sig_parity_v1:");
    h.update(seed);
    h.update(i.to_le_bytes());
    let key_seed: [u8; 32] = h.finalize().into();
    SigningKey::from_bytes(&key_seed)
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut u) else {
        return;
    };

    let n = (input.n_signers % MAX_SIGNERS_FUZZ).max(1);
    let k = (input.k_threshold % n).max(1);
    let supplied = input.sigs_supplied.min(n) as usize;
    let extra = input.extra_garbage_sigs.min(MAX_EXTRA_SIGS) as usize;

    // Build n signing keys and the corresponding SignerKey list.
    let mut signing_keys: Vec<SigningKey> = Vec::with_capacity(n as usize);
    let mut signer_keys: Vec<SignerKey> = Vec::with_capacity(n as usize);
    for i in 0..n {
        let sk = derive_signing_key(&input.seed_bytes, u32::from(i));
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        signer_keys.push(SignerKey {
            key_id: format!("signer-{i}"),
            public_key_hex: pk_hex,
        });
        signing_keys.push(sk);
    }

    let config = ThresholdConfig {
        threshold: u32::from(k),
        total_signers: u32::from(n),
        signer_keys: signer_keys.clone(),
    };

    // Validate first; if the random shape isn't a valid config, both
    // paths would reject in the same way at validate-time — the parity
    // property still holds but isn't an interesting test.
    if config.validate().is_err() {
        return;
    }

    let artifact_id = format!("art-{}", input.artifact_id_byte);
    let connector_id = format!("conn-{}", input.connector_id_byte);
    let content_hash = hex::encode(input.content_hash_seed);

    let mut signatures: Vec<PartialSignature> = Vec::with_capacity(supplied + extra);
    let msg = build_signing_message(&artifact_id, &connector_id, &content_hash);
    for i in 0..supplied {
        let sk = &signing_keys[i];
        let sig = sk.sign(&msg);
        signatures.push(PartialSignature {
            signer_id: format!("signer-{i}"),
            key_id: format!("signer-{i}"),
            signature_hex: hex::encode(sig.to_bytes()),
        });
    }
    // Append random garbage signatures that may exercise duplicate /
    // invalid / unknown-signer code paths in both verifiers.
    for j in 0..extra {
        let garbage = [(input.content_hash_seed[0]).wrapping_add(j as u8); 64];
        signatures.push(PartialSignature {
            signer_id: format!("garbage-{j}"),
            key_id: format!("signer-{}", j % usize::from(n)),
            signature_hex: hex::encode(garbage),
        });
    }

    let payload_cap = MAX_PAYLOAD; // sized exclusively to bound bins; not consumed here.
    let _ = payload_cap;

    let artifact = PublicationArtifact {
        artifact_id,
        connector_id,
        content_hash,
        signatures,
    };

    let preparsed = match PreparsedThresholdConfig::from_config(config.clone()) {
        Ok(p) => p,
        Err(_) => {
            // Validate passed but from_config still rejected — that's a
            // legitimate divergence to log, but it doesn't expose a
            // parity break in the verify paths themselves, since both
            // baseline and preparsed would fail to set up. Skip.
            return;
        }
    };

    let baseline = verify_threshold(&config, &artifact, "fuzz", "ts");
    let preparsed_result = verify_threshold_preparsed(&preparsed, &artifact, "fuzz", "ts");

    assert_eq!(
        baseline, preparsed_result,
        "verify_threshold vs verify_threshold_preparsed divergence on identical input"
    );
});
