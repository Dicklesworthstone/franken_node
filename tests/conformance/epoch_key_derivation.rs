//! Conformance tests for bd-3cs3 epoch-scoped key derivation vectors.

use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use frankenengine_node::security::epoch_scoped_keys::{
    DERIVED_KEY_LEN, RootSecret, derive_epoch_key, sign_epoch_artifact, verify_epoch_signature,
};
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;
use std::fs;
use std::path::Path;
use std::time::Instant;

const VECTOR_REL: &str = "artifacts/10.14/epoch_key_vectors.json";
const LEGACY_KDF_SALT: &[u8] = b"franken-node.epoch-kdf.v1";

fn vector_path() -> std::path::PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut root = manifest.to_path_buf();
    loop {
        let candidate = root.join(VECTOR_REL);
        if candidate.exists() {
            return candidate;
        }
        if !root.pop() {
            break;
        }
    }
    std::path::PathBuf::from(VECTOR_REL)
}

#[derive(Debug, Deserialize)]
struct VectorBundle {
    info_format: String,
    vectors: Vec<KeyVector>,
}

#[derive(Debug, Deserialize)]
struct KeyVector {
    root_secret_hex: String,
    epoch: u64,
    domain: String,
    expected_key_hex: String,
}

fn derive_legacy_v1_unprefixed_hex(root_secret: &RootSecret, epoch: u64, domain: &str) -> String {
    let hkdf = Hkdf::<Sha256>::new(Some(LEGACY_KDF_SALT), root_secret.as_bytes());
    let info = format!("franken-node:epoch={epoch}:domain={domain}");
    let mut okm = [0u8; DERIVED_KEY_LEN];
    hkdf.expand(info.as_bytes(), &mut okm)
        .expect("legacy HKDF expansion");
    hex::encode(okm)
}

#[test]
fn published_epoch_key_vectors_match_derivation() {
    let raw = fs::read_to_string(vector_path()).expect("vector artifact must exist");
    let bundle: VectorBundle = serde_json::from_str(&raw).expect("vector json must parse");

    assert_eq!(
        bundle.info_format,
        "franken-node:epoch={epoch}:domain={domain}"
    );
    assert_eq!(
        bundle.vectors.len(),
        10,
        "expected exactly 10 key vectors in published artifact"
    );

    for vector in bundle.vectors {
        let root_secret = RootSecret::from_hex(&vector.root_secret_hex).expect("sec hex hex");
        // Verify published v1.0 artifact vector against its declared info_format,
        // and verify live length-prefixed derive_epoch_key (INV-EPOCH-KDF-LENGTH-PREFIXED)
        // never collides with unprefixed legacy derivations.
        assert_eq!(
            derive_legacy_v1_unprefixed_hex(&root_secret, vector.epoch, &vector.domain),
            vector.expected_key_hex,
            "legacy v1.0 vector mismatch for epoch={} domain={}",
            vector.epoch,
            vector.domain
        );
        let key = derive_epoch_key(
            &root_secret,
            ControlEpoch::new(vector.epoch),
            &vector.domain,
        );
        assert_ne!(
            key.to_hex(),
            vector.expected_key_hex,
            "length-prefixed KDF must stay domain-separated from unprefixed v1.0 vector for epoch={} domain={}",
            vector.epoch,
            vector.domain
        );
        if vector.epoch == 1 && vector.domain == "marker" {
            assert_eq!(
                key.to_hex(),
                "688a015b0a37cc066e81340ef9dcae5b5936f02a355b132dead9f03b18b345ba"
            );
        }
        if vector.epoch == 13 && vector.domain == "marker" {
            assert_eq!(
                key.to_hex(),
                "d7350d1a4c2204ef30e35ef14064aee424caf6a0d93edb99da9399a80d45c4da"
            );
        }
    }
}

#[test]
fn verify_rejects_cross_epoch_and_cross_domain_signatures() {
    let root_secret =
        RootSecret::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("sec hex");
    let artifact = b"vector-artifact";

    let sig = sign_epoch_artifact(artifact, ControlEpoch::new(21), "marker", &root_secret)
        .expect("signature");

    let epoch_mismatch = verify_epoch_signature(
        artifact,
        &sig,
        ControlEpoch::new(22),
        "marker",
        &root_secret,
    );
    assert!(epoch_mismatch.is_err());

    let domain_mismatch = verify_epoch_signature(
        artifact,
        &sig,
        ControlEpoch::new(21),
        "manifest",
        &root_secret,
    );
    assert!(domain_mismatch.is_err());
}

#[test]
fn derivation_throughput_meets_minimum_budget() {
    let root_secret =
        RootSecret::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("sec hex");
    let iterations: u64 = 10_000;

    let start = Instant::now();
    for i in 0..iterations {
        let epoch = ControlEpoch::new(1 + (i % 257));
        let domain = if i % 2 == 0 { "marker" } else { "manifest" };
        let _ = derive_epoch_key(&root_secret, epoch, domain);
    }
    let elapsed = start.elapsed().as_secs_f64();
    let keys_per_second = iterations as f64 / elapsed.max(f64::MIN_POSITIVE);

    assert!(
        keys_per_second >= 10_000.0,
        "expected >= 10_000 keys/sec, got {:.2} keys/sec over {} iterations",
        keys_per_second,
        iterations
    );
}
