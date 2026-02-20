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
    let raw = fs::read_to_string("artifacts/10.14/epoch_key_vectors.json")
        .expect("vector artifact must exist");
    let bundle: VectorBundle = serde_json::from_str(&raw).expect("vector json must parse");

    assert!(
        bundle.vectors.len() >= 10,
        "expected at least 10 key vectors"
    );

    for vector in bundle.vectors {
        let root_secret = RootSecret::from_hex(&vector.root_secret_hex).expect("root secret hex");
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
            .expect("root secret");
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
