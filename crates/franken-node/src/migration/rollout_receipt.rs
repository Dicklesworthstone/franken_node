//! Signed rollout state revisions and independently verifiable history links.
//!
//! This protocol is separate from validator attestations: an operator key signs
//! the complete persisted state, including recovery intent, history and context.
//! A valid signature does not establish freshness or prove that the controller
//! ran honestly. An independently retained head hash detects replay to a different
//! revision. Losing both that checkpoint and the local history loses that proof.

use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};

pub const SCHEMA: &str = "franken-node/signed-rollout-state/v1";
pub const STATE_SCHEMA: &str = "franken-node/migration-rollout-state/v1";
pub const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;
// A JSON string can expand each state byte to six bytes. Bound BEFORE parsing.
pub const MAX_RECEIPT_BYTES: usize = MAX_STATE_BYTES * 6 + 16 * 1024;
pub const MAX_CHAIN_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CHAIN_REVISIONS: u64 = 1024;
const DOMAIN: &[u8] = b"franken-node/rollout-state-revision/v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: String,
    project_path: String,
    state_file: String,
    revision: u64,
    previous_sha256: Option<String>,
    public_key: String,
    signature: String,
    state_json: String,
}

// Deliberately not Debug/Serialize: state bytes can contain private metadata.
pub struct VerifiedReceipt {
    revision: u64,
    previous_sha256: Option<String>,
    receipt_sha256: String,
    state_sha256: String,
    state_json: String,
}

impl VerifiedReceipt {
    pub fn revision(&self) -> u64 { self.revision }
    pub fn previous_sha256(&self) -> Option<&str> { self.previous_sha256.as_deref() }
    pub fn receipt_sha256(&self) -> &str { &self.receipt_sha256 }
    pub fn state_sha256(&self) -> &str { &self.state_sha256 }
    pub fn state_bytes(&self) -> &[u8] { self.state_json.as_bytes() }
    pub fn into_state(self) -> Vec<u8> { self.state_json.into_bytes() }
}

pub fn sha256(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

fn decode<const N: usize>(text: &str) -> Result<[u8; N]> {
    ensure!(text.len() == N * 2 && text.bytes().all(|b|
        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "rollout receipt requires canonical lowercase hexadecimal");
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes)?;
    Ok(bytes)
}

pub fn public_key(text: &str) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(&decode(text)?)?;
    ensure!(!key.is_weak(), "weak rollout authority key refused");
    Ok(key)
}

pub fn receipt_name(hash: &str) -> Result<String> {
    decode::<32>(hash)?;
    Ok(format!(".signed-{hash}.json"))
}

fn context(project: &str, name: &str) -> Result<()> {
    let path = Path::new(project);
    let normalized: std::path::PathBuf = path.components().collect();
    ensure!(project.len() <= 4096 && path.is_absolute() && normalized.to_str() == Some(project)
        && path.components().all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "rollout receipt project must be an absolute normalized path");
    let id = name.strip_suffix(".json").context("rollout state filename must end in .json")?;
    ensure!(!id.is_empty() && id.len() <= 96 && id.bytes().all(|b|
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "invalid rollout receipt state filename");
    Ok(())
}

fn state_identity(raw: &[u8], project: &str, name: &str) -> Result<()> {
    ensure!(!raw.is_empty() && raw.len() <= MAX_STATE_BYTES, "rollout state exceeds 2 MiB");
    #[derive(Deserialize)]
    struct Identity { schema_version: String, migration_id: String, project_path: String }
    let identity: Identity = serde_json::from_slice(raw).context("invalid rollout state identity")?;
    ensure!(identity.schema_version == STATE_SCHEMA && identity.project_path == project
        && name == format!("{}.json", identity.migration_id),
        "signed rollout state identity disagrees with its project or migration context");
    Ok(())
}

fn message(envelope: &Envelope) -> Result<Vec<u8>> {
    ensure!(!envelope.state_json.is_empty() && envelope.state_json.len() <= MAX_STATE_BYTES,
        "rollout state exceeds 2 MiB");
    ensure!(envelope.revision > 0 && (envelope.revision == 1) == envelope.previous_sha256.is_none(),
        "rollout receipt revision and predecessor disagree");
    let mut message = DOMAIN.to_vec();
    for text in [&envelope.project_path, &envelope.state_file] {
        message.extend_from_slice(&(text.len() as u64).to_le_bytes());
        message.extend_from_slice(text.as_bytes());
    }
    message.extend_from_slice(&envelope.revision.to_le_bytes());
    message.push(u8::from(envelope.previous_sha256.is_some()));
    if let Some(hash) = &envelope.previous_sha256 {
        message.extend_from_slice(&decode::<32>(hash)?);
    }
    message.extend_from_slice(&(envelope.state_json.len() as u64).to_le_bytes());
    message.extend_from_slice(envelope.state_json.as_bytes());
    Ok(message)
}

/// Authenticate the exact state bytes BEFORE interpreting their identity.
/// Expected context and the trusted key come from the caller, not the envelope.
pub fn verify(raw: &[u8], trusted: &VerifyingKey, project: &str, name: &str) -> Result<VerifiedReceipt> {
    ensure!(raw.len() <= MAX_RECEIPT_BYTES, "rollout receipt exceeds its byte budget");
    context(project, name)?;
    ensure!(!trusted.is_weak(), "weak rollout authority key refused");
    let envelope: Envelope = serde_json::from_slice(raw).context("invalid signed rollout state")?;
    ensure!(envelope.schema_version == SCHEMA, "unsupported rollout receipt schema");
    ensure!(envelope.project_path == project && envelope.state_file == name,
        "rollout receipt belongs to a different project or migration");
    ensure!(decode::<32>(&envelope.public_key)? == trusted.to_bytes(),
        "rollout signer differs from the independently trusted operator key");
    let signature = Signature::from_bytes(&decode::<64>(&envelope.signature)?);
    trusted.verify_strict(&message(&envelope)?, &signature)
        .context("rollout state signature verification failed")?;
    ensure!(serde_json::to_vec(&envelope)? == raw, "noncanonical rollout receipt encoding");
    state_identity(envelope.state_json.as_bytes(), project, name)?;
    Ok(VerifiedReceipt {
        revision: envelope.revision,
        previous_sha256: envelope.previous_sha256,
        receipt_sha256: sha256(raw),
        state_sha256: sha256(envelope.state_json.as_bytes()),
        state_json: envelope.state_json,
    })
}

/// Trusted persistence primitive, not a sign-import operator. A non-genesis
/// write must extend an authenticated predecessor in exactly the same context.
pub fn seal(state: &[u8], key: &SigningKey, project: &str, name: &str,
    previous: Option<&[u8]>) -> Result<Vec<u8>> {
    context(project, name)?;
    state_identity(state, project, name)?;
    let previous = previous.map(|raw| verify(raw, &key.verifying_key(), project, name)).transpose()?;
    let revision = match &previous {
        Some(previous) => previous.revision.checked_add(1).context("rollout receipt revision overflow")?,
        None => 1,
    };
    let mut envelope = Envelope {
        schema_version: SCHEMA.into(), project_path: project.into(), state_file: name.into(),
        revision, previous_sha256: previous.map(|receipt| receipt.receipt_sha256),
        public_key: hex::encode(key.verifying_key().to_bytes()), signature: String::new(),
        state_json: std::str::from_utf8(state)?.into(),
    };
    envelope.signature = hex::encode(key.sign(&message(&envelope)?).to_bytes());
    let raw = serde_json::to_vec(&envelope)?;
    ensure!(raw.len() <= MAX_RECEIPT_BYTES, "rollout receipt exceeds its byte budget");
    Ok(raw)
}

#[derive(Debug, Serialize)]
pub struct ChainVerification {
    pub schema_version: String,
    pub project_path: String,
    pub state_file: String,
    pub head_sha256: String,
    pub state_sha256: String,
    pub revision: u64,
    pub receipts_verified: u64,
    pub externally_pinned: bool,
    pub execution_performed: bool,
    pub currentness_proven: bool,
}

/// Verify every signed predecessor back to genesis using content-addressed
/// receipts. The loader is read-only and receives only a validated SHA-256.
/// A complete old chain is authentic but not necessarily current: retain the
/// head pin through an independent channel when replay detection is required.
pub fn verify_chain(head: &[u8], trusted: &VerifyingKey, project: &str, name: &str,
    expected_head: Option<&str>, mut load: impl FnMut(&str) -> Result<Vec<u8>>) -> Result<ChainVerification> {
    if let Some(pin) = expected_head {
        decode::<32>(pin)?;
        ensure!(pin == sha256(head), "rollout head differs from the independently retained checkpoint");
    }
    let mut current = verify(head, trusted, project, name)?;
    ensure!(current.revision <= MAX_CHAIN_REVISIONS, "rollout history verification revision budget exceeded");
    let mut result = ChainVerification {
        schema_version: "franken-node/rollout-history-verification/v1".into(),
        project_path: project.into(), state_file: name.into(),
        head_sha256: current.receipt_sha256.clone(), state_sha256: current.state_sha256.clone(),
        revision: current.revision, receipts_verified: 1, externally_pinned: expected_head.is_some(),
        execution_performed: false, currentness_proven: false,
    };
    let mut bytes = head.len();
    while let Some(hash) = current.previous_sha256.as_deref() {
        let raw = load(hash).context("signed rollout predecessor is unavailable")?;
        bytes = bytes.checked_add(raw.len()).context("rollout history byte count overflow")?;
        ensure!(bytes <= MAX_CHAIN_BYTES, "rollout history exceeds 64 MiB verification budget");
        ensure!(sha256(&raw) == hash, "rollout predecessor content hash mismatch");
        let previous = verify(&raw, trusted, project, name)?;
        ensure!(previous.revision.checked_add(1) == Some(current.revision),
            "rollout history revisions are not consecutive");
        current = previous;
        result.receipts_verified += 1;
    }
    ensure!(result.receipts_verified == result.revision && current.revision == 1,
        "rollout history does not reach its signed genesis");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn state(note: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"schema_version":STATE_SCHEMA,
            "migration_id":"mig-one", "project_path":"/project", "history":[note]})).unwrap()
    }
    fn signed(note: &str, previous: Option<&[u8]>) -> Vec<u8> {
        seal(&state(note), &SigningKey::from_bytes(&[7;32]), "/project", "mig-one.json", previous).unwrap()
    }
    fn trusted() -> VerifyingKey { SigningKey::from_bytes(&[7;32]).verifying_key() }

    #[test]
    fn independent_ed25519_vector_binds_context_revision_and_state_bytes() {
        // Fixed vector generated using Python cryptography, not this Rust signer.
        let raw = br#"{"schema_version":"franken-node/migration-rollout-state/v1","migration_id":"mig-one","project_path":"/project","history":[]}"#;
        let expected = br#"{"schema_version":"franken-node/signed-rollout-state/v1","project_path":"/project","state_file":"mig-one.json","revision":1,"previous_sha256":null,"public_key":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","signature":"55502d4e8767c302172e94fbc19c5c30b02cf794512259406be3fab6ca5e3ad5f16d6e8b668f3e0a8d6e9f651758db1fd52043df45db2c52f8329b233b85a10f","state_json":"{\"schema_version\":\"franken-node/migration-rollout-state/v1\",\"migration_id\":\"mig-one\",\"project_path\":\"/project\",\"history\":[]}"}"#;
        assert_eq!(seal(raw, &SigningKey::from_bytes(&[7;32]), "/project", "mig-one.json", None).unwrap(), expected);
        assert_eq!(verify(expected, &trusted(), "/project", "mig-one.json").unwrap().state_bytes(), raw);
    }

    #[test]
    fn exact_state_bytes_and_full_history_are_authenticated() {
        let raw = signed("private reason π", None);
        let verified = verify(&raw, &trusted(), "/project", "mig-one.json").unwrap();
        assert_eq!(verified.state_bytes(), state("private reason π"));
        assert_eq!(verified.revision(), 1);
        assert_eq!(verified.previous_sha256(), None);
        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        value["state_json"] = String::from_utf8(state("fabricated history")).unwrap().into();
        assert!(verify(&serde_json::to_vec(&value).unwrap(), &trusted(), "/project", "mig-one.json").is_err());
    }

    #[test]
    fn signer_project_and_migration_are_independent_authorities() {
        let raw = signed("initial", None);
        for (key, project, name) in [(SigningKey::from_bytes(&[8;32]).verifying_key(), "/project", "mig-one.json"),
            (trusted(), "/other", "mig-one.json"), (trusted(), "/project", "mig-other.json")] {
            assert!(verify(&raw, &key, project, name).is_err());
        }
        assert!(seal(&state("new"), &SigningKey::from_bytes(&[8;32]), "/project", "mig-one.json", Some(&raw)).is_err());
    }

    #[test]
    fn duplicate_unknown_noncanonical_and_unsigned_envelopes_fail_closed() {
        let raw = signed("initial", None);
        let text = std::str::from_utf8(&raw).unwrap();
        for name in ["signature", "revision", "state_json", "previous_sha256", "ignore_signature"] {
            let changed = format!("{{\"{name}\":null,{}", &text[1..]);
            assert!(verify(changed.as_bytes(), &trusted(), "/project", "mig-one.json").is_err());
        }
        let spaced = format!(" {text}");
        assert!(verify(spaced.as_bytes(), &trusted(), "/project", "mig-one.json").is_err());
        assert!(verify(&state("unsigned"), &trusted(), "/project", "mig-one.json").is_err());
    }

    #[test]
    fn revision_and_predecessor_cannot_be_rewritten() {
        let first = signed("one", None);
        let second = signed("two", Some(&first));
        for (field, value) in [("revision", serde_json::json!(1)),
            ("previous_sha256", serde_json::Value::Null),
            ("previous_sha256", serde_json::json!("a".repeat(64))),
            ("schema_version", serde_json::json!("other/v1"))] {
            let mut changed: serde_json::Value = serde_json::from_slice(&second).unwrap();
            changed[field] = value;
            assert!(verify(&serde_json::to_vec(&changed).unwrap(), &trusted(), "/project", "mig-one.json").is_err());
        }
    }

    #[test]
    fn every_predecessor_is_verified_to_genesis() {
        let first = signed("one", None);
        let second = signed("two", Some(&first));
        let third = signed("three", Some(&second));
        let archive = BTreeMap::from([(sha256(&first), first), (sha256(&second), second)]);
        let report = verify_chain(&third, &trusted(), "/project", "mig-one.json", Some(&sha256(&third)),
            |hash| Ok(archive[hash].clone())).unwrap();
        assert_eq!(report.receipts_verified, 3);
        assert!(report.externally_pinned);
        assert!(!report.execution_performed && !report.currentness_proven);
        assert!(verify_chain(&third, &trusted(), "/project", "mig-one.json", None,
            |_| anyhow::bail!("missing receipt")).is_err());
        assert!(verify_chain(&third, &trusted(), "/project", "mig-one.json", None,
            |_| Ok(signed("substitution", None))).is_err());
    }

    #[test]
    fn retained_checkpoint_detects_replay_of_an_authentic_old_head() {
        let old = signed("old", None);
        let new = signed("new", Some(&old));
        assert!(verify(&old, &trusted(), "/project", "mig-one.json").is_ok());
        assert!(verify_chain(&old, &trusted(), "/project", "mig-one.json", Some(&sha256(&new)),
            |_| unreachable!()).is_err());
    }

    #[test]
    fn signed_bytes_cannot_cross_from_another_protocol() {
        let raw = signed("initial", None);
        let mut envelope: Envelope = serde_json::from_slice(&raw).unwrap();
        envelope.signature = hex::encode(SigningKey::from_bytes(&[7;32]).sign(envelope.state_json.as_bytes()).to_bytes());
        assert!(verify(&serde_json::to_vec(&envelope).unwrap(), &trusted(), "/project", "mig-one.json").is_err());
    }

    #[test]
    fn weak_keys_invalid_contexts_and_unbounded_payloads_are_refused() {
        assert!(public_key(&format!("01{}", "00".repeat(31))).is_err());
        assert!(public_key(&"F".repeat(64)).is_err());
        for name in ["../mig-one.json", "mig-one", "mig-one.json/", ".json"] {
            assert!(seal(&state("a"), &SigningKey::from_bytes(&[7;32]), "/project", name, None).is_err());
        }
        assert!(seal(&vec![b'x';MAX_STATE_BYTES+1], &SigningKey::from_bytes(&[7;32]), "/project", "mig-one.json", None).is_err());
        assert!(seal(b"{}", &SigningKey::from_bytes(&[7;32]), "/project", "mig-one.json", None).is_err());
        assert!(receipt_name("../other").is_err());
    }
}
