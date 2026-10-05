//! Domain-separated Ed25519 attestation of exact migration report bytes.
//!
//! The signer identity in an envelope is descriptive, never a trust anchor.
//! Verification requires an independently provisioned public key. Possession
//! of that key's secret grants attestation authority; signatures do not prove
//! that the signer, runtime, tests, or ambient execution environment are safe.

use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

#[path = "rollout_receipt.rs"]
pub mod rollout_receipt;

pub const SCHEMA: &str = "franken-node/signed-product-validation/v1";
pub const PRODUCT_SCHEMA: &str = "franken-node/product-validation-suite/v1";
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
pub const PUBLIC_KEY_PATH: &str = ".franken-node/keys/migration-validation.pub";
const DOMAIN: &[u8] = b"franken-node/migration-validation-attestation/v1\0";

/// report_json retains the exact signed bytes: never reserialize a parsed
/// report to verify its signature. Duplicate envelope keys are rejected by
/// serde's struct deserializer, as are missing and unknown envelope fields.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: String,
    public_key: String,
    signature: String,
    report_json: String,
}

fn decode<const N: usize>(value: &str) -> Result<[u8; N]> {
    ensure!(
        value.len() == N * 2
            && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "attestation keys and signatures require canonical lowercase hexadecimal"
    );
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).context("invalid attestation hexadecimal")?;
    Ok(bytes)
}

pub fn public_key(text: &str) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(&decode(text)?).context("invalid Ed25519 public key")?;
    ensure!(!key.is_weak(), "weak Ed25519 attestation public key refused");
    Ok(key)
}

fn message(report: &[u8]) -> Result<Vec<u8>> {
    ensure!(!report.is_empty() && report.len() <= MAX_BYTES, "report exceeds attestation bounds");
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 8 + report.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&(report.len() as u64).to_le_bytes());
    bytes.extend_from_slice(report);
    Ok(bytes)
}

/// Cryptographic primitive for trusted callers. The operator executable signs
/// only its own freshly executed passing ProductReport; it offers no command
/// that signs an imported report. A holder of the secret key can still make
/// arbitrary attestations, as with every digital signature system.
pub fn seal(report: &[u8], key: &SigningKey) -> Result<Vec<u8>> {
    let signature = key.sign(&message(report)?);
    let report_json = std::str::from_utf8(report).context("report must be UTF-8 JSON")?;
    let schema: serde_json::Value = serde_json::from_str(report_json)?;
    ensure!(schema.get("schema_version").and_then(|v| v.as_str()) == Some(PRODUCT_SCHEMA),
        "only product-validation reports may be attested");
    let raw = serde_json::to_vec(&Envelope {
        schema_version: SCHEMA.into(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
        report_json: report_json.into(),
    })?;
    ensure!(raw.len() <= MAX_BYTES, "signed report envelope exceeds 16 MiB");
    Ok(raw)
}

/// Authenticate before parsing or trusting any product report fields. No
/// self-signed fallback, schema fallback, or automatic trust-key installation.
pub fn verify(raw: &[u8], trusted: &VerifyingKey) -> Result<Vec<u8>> {
    ensure!(raw.len() <= MAX_BYTES, "signed report envelope exceeds 16 MiB");
    ensure!(!trusted.is_weak(), "weak trusted Ed25519 public key refused");
    let envelope: Envelope = serde_json::from_slice(raw).context("invalid signed report envelope")?;
    ensure!(envelope.schema_version == SCHEMA, "unsupported report attestation schema");
    ensure!(decode::<32>(&envelope.public_key)? == trusted.to_bytes(),
        "report signer is not the independently trusted validation key");
    let signature = Signature::from_bytes(&decode::<64>(&envelope.signature)?);
    trusted.verify_strict(&message(envelope.report_json.as_bytes())?, &signature)
        .context("migration report signature verification failed")?;
    Ok(envelope.report_json.into_bytes())
}

/// Read a public trust anchor relative to the existing project, without
/// following a symlink at any configuration component. No key is learned
/// from the supplied report. The anchor is captured with other project inputs.
#[cfg(target_os = "linux")]
pub fn project_key(project: &std::path::Path) -> Result<VerifyingKey> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let root = project.canonicalize().context("resolve attestation project")?;
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut dir = open(&root, dir_flags, Mode::empty())?;
    for component in [".franken-node", "keys"] {
        dir = openat(&dir, component, dir_flags, Mode::empty())
            .context("validation trust-key directory missing or linked")?;
    }
    let mut file = File::from(openat(&dir, "migration-validation.pub",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty()).context("install the independent migration-validation.pub trust key")?);
    let before = file.metadata()?;
    ensure!(before.is_file() && before.len() <= 66 && before.nlink() == 1,
        "validation trust key must be a bounded regular unlinked file");
    let mut raw = Vec::new();
    file.by_ref().take(67).read_to_end(&mut raw)?;
    let after = file.metadata()?;
    ensure!(raw.len() <= 66 && before.len() == after.len()
        && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec(),
        "validation trust key changed while reading");
    let text = std::str::from_utf8(&raw).context("validation public key must be hexadecimal")?;
    public_key(text.strip_suffix("\r\n").or_else(|| text.strip_suffix('\n')).unwrap_or(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_ed25519_vector_pins_domain_length_and_exact_bytes() {
        // Produced with Python cryptography's Ed25519 implementation, not
        // derived by the Rust signing code under test.
        let raw = br#"{"schema_version":"franken-node/product-validation-suite/v1","verdict":"PASS"}"#;
        let trusted = public_key("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c").unwrap();
        let envelope = Envelope {
            schema_version: SCHEMA.into(),
            public_key: hex::encode(trusted.to_bytes()),
            signature: "15e85bb9e56c8134ddc41650b972a58eee1dea216721ac56e293385ff8c6a5c42d7f2ebef0439526b13ebf68ce9290c6d42cbe2128de4c2dd4fb1d3fb61ff808".into(),
            report_json: std::str::from_utf8(raw).unwrap().into(),
        };
        let encoded = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(verify(&encoded, &trusted).unwrap(), raw);
        assert_eq!(seal(raw, &SigningKey::from_bytes(&[7; 32])).unwrap(), encoded);
    }

    fn report() -> Vec<u8> {
        format!(r#"{{"schema_version":"{PRODUCT_SCHEMA}","verdict":"PASS","note":"π\\n"}}"#).into_bytes()
    }

    #[test]
    fn exact_bytes_round_trip_without_reserialization() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut raw = b" \n".to_vec();
        raw.extend(report());
        let sealed = seal(&raw, &key).unwrap();
        assert_eq!(verify(&sealed, &key.verifying_key()).unwrap(), raw);
    }

    #[test]
    fn wrong_key_and_self_provided_key_are_not_trusted() {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let trusted = SigningKey::from_bytes(&[8; 32]).verifying_key();
        assert!(verify(&seal(&report(), &signer).unwrap(), &trusted).is_err());
    }

    #[test]
    fn modified_report_signature_or_signer_is_rejected() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let sealed = seal(&report(), &key).unwrap();
        for field in ["report_json", "signature", "public_key", "schema_version"] {
            let mut changed: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
            let value = changed[field].as_str().unwrap().to_owned() + " ";
            changed[field] = value.into();
            assert!(verify(&serde_json::to_vec(&changed).unwrap(), &key.verifying_key()).is_err(), "{field}");
        }
    }

    #[test]
    fn envelope_duplicates_unknown_fields_and_unsigned_reports_are_refused() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let sealed = String::from_utf8(seal(&report(), &key).unwrap()).unwrap();
        for field in ["schema_version", "public_key", "signature", "report_json", "ignore_signature"] {
            let ambiguous = format!("{{\"{field}\":\"x\",{}", &sealed[1..]);
            assert!(verify(ambiguous.as_bytes(), &key.verifying_key()).is_err());
        }
        assert!(verify(&report(), &key.verifying_key()).is_err());
    }

    #[test]
    fn signing_domain_is_not_a_bare_report_or_other_protocol() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let raw = report();
        let mut envelope: serde_json::Value = serde_json::from_slice(&seal(&raw, &key).unwrap()).unwrap();
        envelope["signature"] = hex::encode(key.sign(&raw).to_bytes()).into();
        assert!(verify(&serde_json::to_vec(&envelope).unwrap(), &key.verifying_key()).is_err());
    }

    #[test]
    fn malformed_weak_keys_and_size_limits_fail_closed() {
        for key in ["".into(), "f".repeat(63), "F".repeat(64), "01".to_owned() + &"00".repeat(31)] {
            assert!(public_key(&key).is_err());
        }
        let key = SigningKey::from_bytes(&[7; 32]);
        assert!(seal(b"{}", &key).is_err());
        assert!(seal(&vec![b'x'; MAX_BYTES + 1], &key).is_err());
        assert!(verify(&vec![b'x'; MAX_BYTES + 1], &key.verifying_key()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn project_anchor_rejects_symlink_parents_and_never_learns_a_key() {
        use std::{fs, os::unix::fs::symlink};
        let root = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        assert!(project_key(root.path()).is_err());
        fs::create_dir_all(root.path().join(".franken-node/keys")).unwrap();
        fs::write(root.path().join(PUBLIC_KEY_PATH), hex::encode(key.to_bytes())).unwrap();
        assert_eq!(project_key(root.path()).unwrap(), key);
        fs::rename(root.path().join(PUBLIC_KEY_PATH), root.path().join("original-key")).unwrap();
        symlink("../../original-key", root.path().join(PUBLIC_KEY_PATH)).unwrap();
        assert!(project_key(root.path()).is_err());
        let linked = tempfile::tempdir().unwrap();
        symlink(root.path().join(".franken-node"), linked.path().join(".franken-node")).unwrap();
        assert!(project_key(linked.path()).is_err());
    }
}
