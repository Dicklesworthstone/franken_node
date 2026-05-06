//! Golden artifact tests for supply_chain::artifact_signing module.
//!
//! Freezes the deterministic ChecksumManifest canonical bytes, signature payload,
//! and manifest JSON envelope so release signing format changes require review.

use std::{fs, path::PathBuf};

use frankenengine_node::supply_chain::artifact_signing::{
    AuditLogEntry, ChecksumManifest, build_and_sign_manifest, signing_key_from_seed_hex,
};
use serde_json::{Value, json};
use sha2::Digest;

const FIXTURE_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/artifact_signing")
        .join(format!("{name}.golden"))
}

fn assert_golden(name: &str, actual: &str) {
    let golden_path = golden_path(name);
    let actual = if actual.ends_with('\n') {
        actual.to_string()
    } else {
        format!("{actual}\n")
    };

    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(golden_path.parent().expect("golden path has parent"))
            .expect("create artifact-signing golden directory");
        fs::write(&golden_path, actual).expect("write artifact-signing golden");
        return;
    }

    let expected = fs::read_to_string(&golden_path)
        .unwrap_or_else(|err| panic!("read golden {}: {err}", golden_path.display()));
    if expected != actual {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, actual).expect("write artifact-signing actual");
        panic!(
            "artifact-signing golden mismatch for {}; wrote actual to {}",
            golden_path.display(),
            actual_path.display()
        );
    }
}

fn fixture_manifest() -> ChecksumManifest {
    let signing_key = signing_key_from_seed_hex(FIXTURE_SEED_HEX).expect("fixture seed is valid");
    build_and_sign_manifest(
        &[
            (
                "bin/franken-node-linux-x64.tar.gz",
                b"linux-release-bits" as &[u8],
            ),
            (
                "checksums/SHA256SUMS",
                b"prior-checksum-placeholder" as &[u8],
            ),
            (
                "docs/release-notes.md",
                b"# Franken Node 0.1.0\n\n- harden signing\n" as &[u8],
            ),
        ],
        &signing_key,
    )
}

fn manifest_json(manifest: &ChecksumManifest) -> Value {
    let entries = manifest
        .entries
        .values()
        .map(|entry| {
            json!({
                "name": entry.name,
                "sha256": entry.sha256,
                "size_bytes": entry.size_bytes,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "schema_version": "franken-node/artifact-signing-manifest-golden/v1",
        "key_id": manifest.key_id.to_string(),
        "signature_hex": hex::encode(&manifest.signature),
        "signature_payload_hex": hex::encode(manifest.canonical_signature_payload()),
        "canonical_manifest_sha256": {
            "algorithm": "sha256",
            "value": hex::encode(sha2::Sha256::digest(manifest.canonical_bytes())),
        },
        "entries": entries,
    })
}

fn scrub_audit_json(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut()
        && object.contains_key("timestamp")
    {
        object.insert("timestamp".to_string(), json!("[TIMESTAMP]"));
    }
    value
}

#[test]
fn artifact_signing_manifest_canonical_bytes_match_golden() {
    let manifest = fixture_manifest();
    let canonical = String::from_utf8(manifest.canonical_bytes()).expect("canonical utf8");

    assert_golden("manifest_canonical_bytes", &canonical);
}

#[test]
fn artifact_signing_manifest_json_envelope_matches_golden() {
    let manifest = fixture_manifest();
    let json = serde_json::to_string_pretty(&manifest_json(&manifest)).expect("manifest json");

    assert_golden("manifest_json_envelope", &json);
}

#[test]
fn artifact_signing_manifest_signature_payload_matches_golden() {
    let manifest = fixture_manifest();
    let payload_hex = hex::encode(manifest.canonical_signature_payload());

    assert_golden("manifest_signature_payload_hex", &payload_hex);
}

#[test]
fn artifact_signing_audit_log_json_scrubs_timestamp() {
    let entry = AuditLogEntry::now(
        "ASV-001",
        "bin/franken-node-linux-x64.tar.gz",
        &fixture_manifest().key_id.to_string(),
        "sign-manifest",
        "success",
    );
    let scrubbed = scrub_audit_json(entry.to_json());
    let json = serde_json::to_string_pretty(&scrubbed).expect("audit json");

    assert_golden("audit_log_entry_json", &json);
}
