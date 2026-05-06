//! Golden artifact tests for supply_chain::artifact_signing module.
//!
//! Freezes the deterministic ChecksumManifest canonical bytes, signature payload,
//! and manifest JSON envelope so release signing format changes require review.

use std::{error::Error, fs, io, path::PathBuf};

use frankenengine_node::supply_chain::artifact_signing::{
    AuditLogEntry, ChecksumManifest, build_and_sign_manifest, signing_key_from_seed_hex,
};
use serde_json::{Value, json};
use sha2::Digest;

const FIXTURE_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

type TestResult = Result<(), Box<dyn Error>>;

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/artifact_signing")
        .join(format!("{name}.golden"))
}

fn assert_golden(name: &str, actual: &str) -> TestResult {
    let golden_path = golden_path(name);
    let actual = if actual.ends_with('\n') {
        actual.to_string()
    } else {
        format!("{actual}\n")
    };

    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        let parent = golden_path
            .parent()
            .ok_or_else(|| io::Error::other("golden path has no parent directory"))?;
        fs::create_dir_all(parent)?;
        fs::write(&golden_path, actual)?;
        return Ok(());
    }

    let expected = fs::read_to_string(&golden_path)
        .map_err(|err| io::Error::other(format!("read golden {}: {err}", golden_path.display())))?;
    if expected != actual {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, actual)?;
        return Err(io::Error::other(format!(
            "artifact-signing golden mismatch for {}; wrote actual to {}",
            golden_path.display(),
            actual_path.display()
        ))
        .into());
    }

    Ok(())
}

fn fixture_manifest() -> Result<ChecksumManifest, Box<dyn Error>> {
    let signing_key = signing_key_from_seed_hex(FIXTURE_SEED_HEX)?;
    Ok(build_and_sign_manifest(
        &[
            (
                "bin/franken-node-linux-x64.tar.gz",
                b"linux-release-bits" as &[u8],
            ),
            (
                "checksums/SHA256SUMS",
                b"previous release checksum manifest\n" as &[u8],
            ),
            (
                "docs/release-notes.md",
                b"# Franken Node 0.1.0\n\n- harden signing\n" as &[u8],
            ),
        ],
        &signing_key,
    ))
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

#[test]
fn artifact_signing_manifest_fixture_rejects_placeholder_material() -> TestResult {
    let manifest = fixture_manifest()?;
    let canonical = String::from_utf8(manifest.canonical_bytes())?;
    let json = serde_json::to_string_pretty(&manifest_json(&manifest))?;
    let payload_hex = hex::encode(manifest.canonical_signature_payload());
    let signature_hex = hex::encode(&manifest.signature);

    for (sentinel, error_message) in [
        (
            "prior-checksum-placeholder",
            "fixture must not contain placeholder checksum bytes",
        ),
        (
            "deadbeefcafebabe",
            "fixture must not contain sentinel signature bytes",
        ),
        (
            "releasemanifest",
            "fixture must not contain synthetic payload sentinel text",
        ),
    ] {
        for value in [
            canonical.as_str(),
            json.as_str(),
            payload_hex.as_str(),
            signature_hex.as_str(),
        ] {
            if value.contains(sentinel) {
                return Err(io::Error::other(error_message).into());
            }
        }
    }

    Ok(())
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
fn artifact_signing_manifest_canonical_bytes_match_golden() -> TestResult {
    let manifest = fixture_manifest()?;
    let canonical = String::from_utf8(manifest.canonical_bytes())?;

    assert_golden("manifest_canonical_bytes", &canonical)
}

#[test]
fn artifact_signing_manifest_json_envelope_matches_golden() -> TestResult {
    let manifest = fixture_manifest()?;
    let json = serde_json::to_string_pretty(&manifest_json(&manifest))?;

    assert_golden("manifest_json_envelope", &json)
}

#[test]
fn artifact_signing_manifest_signature_payload_matches_golden() -> TestResult {
    let manifest = fixture_manifest()?;
    let payload_hex = hex::encode(manifest.canonical_signature_payload());

    assert_golden("manifest_signature_payload_hex", &payload_hex)
}

#[test]
fn artifact_signing_audit_log_json_scrubs_timestamp() -> TestResult {
    let manifest = fixture_manifest()?;
    let entry = AuditLogEntry::now(
        "ASV-001",
        "bin/franken-node-linux-x64.tar.gz",
        &manifest.key_id.to_string(),
        "sign-manifest",
        "success",
    );
    let scrubbed = scrub_audit_json(entry.to_json());
    let json = serde_json::to_string_pretty(&scrubbed)?;

    assert_golden("audit_log_entry_json", &json)
}
