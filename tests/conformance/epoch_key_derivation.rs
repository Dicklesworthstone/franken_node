//! Conformance tests for bd-3cs3 epoch-scoped key derivation vectors.

#[path = "../../crates/franken-node/src/control_plane/control_epoch.rs"]
pub mod control_epoch;

pub mod control_plane {
    pub use super::control_epoch;
}

#[path = "../../crates/franken-node/src/security/epoch_scoped_keys.rs"]
mod epoch_scoped_keys;

use control_plane::control_epoch::ControlEpoch;
use epoch_scoped_keys::{
    RootSecret, derive_epoch_key, sign_epoch_artifact, verify_epoch_signature,
};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::Instant;

const VECTOR_REL: &str = "artifacts/10.14/epoch_key_vectors.json";

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
    vectors: Vec<KeyVector>,
}

#[derive(Debug, Deserialize)]
struct KeyVector {
    root_secret_hex: String,
    epoch: u64,
    domain: String,
    expected_key_hex: String,
}

#[test]
fn published_epoch_key_vectors_match_derivation() {
    let raw = fs::read_to_string(vector_path()).expect("vector artifact must exist");
    let bundle: VectorBundle = serde_json::from_str(&raw).expect("vector json must parse");

    assert_eq!(
        bundle.vectors.len(),
        10,
        "expected exactly 10 key vectors in published artifact"
    );

    for vector in bundle.vectors {
        let root_secret = RootSecret::from_hex(&vector.root_secret_hex).expect("sec hex hex");
        let key = derive_epoch_key(
            &root_secret,
            ControlEpoch::new(vector.epoch),
            &vector.domain,
        );
        assert_eq!(
            key.to_hex(),
            vector.expected_key_hex,
            "mismatch for epoch={} domain={}",
            vector.epoch,
            vector.domain
        );
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
