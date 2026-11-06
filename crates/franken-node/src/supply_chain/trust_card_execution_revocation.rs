//! Permanent operator denials for authenticated native artifact identities.
//!
//! The enclosing trust-card snapshot authenticates these records and commits
//! them with its existing durable high-water transaction. Publisher display
//! names, package names and unsigned registry extension IDs are not selectors.
//! A record denies execution immediately, independent of its audit timestamp;
//! it does not claim remote propagation or that external effects have stopped.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{TrustCardError, TrustCardRegistry};

const MAX_EXECUTION_REVOCATIONS: usize = 4096;
const MAX_REASON_BYTES: usize = 1024;

/// Exact, independently authenticated execution authority to revoke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionRevocationTarget {
    /// The canonical identifier produced by `artifact_signing::KeyId`.
    PublisherKey { key_id: String },
    /// The full content identity carried by `PublisherArtifactIdentity`.
    Artifact { sha256: String },
}

impl ExecutionRevocationTarget {
    pub fn publisher_key(key_id: &str) -> Result<Self, TrustCardError> {
        if !canonical_hex(key_id, 16) {
            return Err(invalid_target());
        }
        Ok(Self::PublisherKey {
            key_id: key_id.to_string(),
        })
    }

    pub fn artifact_sha256(sha256: &str) -> Result<Self, TrustCardError> {
        if !sha256
            .strip_prefix("sha256:")
            .is_some_and(|digest| canonical_hex(digest, 64))
        {
            return Err(invalid_target());
        }
        Ok(Self::Artifact {
            sha256: sha256.to_string(),
        })
    }

    /// Reject shortened hashes, display labels, aliases and alternate casing.
    /// CLI normalization, when offered, must happen before this boundary.
    pub fn validate(&self) -> Result<(), TrustCardError> {
        let valid = match self {
            // KeyId currently retains the first eight bytes of its
            // domain-separated SHA-256 derivation, encoded as lowercase hex.
            Self::PublisherKey { key_id } => canonical_hex(key_id, 16),
            Self::Artifact { sha256 } => sha256
                .strip_prefix("sha256:")
                .is_some_and(|digest| canonical_hex(digest, 64)),
        };
        if !valid {
            return Err(invalid_target());
        }
        Ok(())
    }

    fn storage_key(&self) -> String {
        match self {
            Self::PublisherKey { key_id } => format!("publisher-key:{key_id}"),
            Self::Artifact { sha256 } => format!("artifact:{sha256}"),
        }
    }
}

/// The first committed denial for one target. Repeating a revocation retains
/// this exact record, including its original timestamp and bounded reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRevocation {
    pub target: ExecutionRevocationTarget,
    pub revoked_at_secs: u64,
    pub reason: String,
}

impl ExecutionRevocation {
    fn validate(&self) -> Result<(), TrustCardError> {
        self.target.validate()?;
        validate_reason(&self.reason)
    }
}

fn canonical_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_target() -> TrustCardError {
    TrustCardError::InvalidInput {
        reason: "execution revocation requires a canonical publisher KeyId or full sha256 artifact identity".to_string(),
    }
}

fn validate_reason(reason: &str) -> Result<(), TrustCardError> {
    if reason.is_empty()
        || reason.len() > MAX_REASON_BYTES
        || reason.trim() != reason
        || reason.chars().any(char::is_control)
    {
        return Err(TrustCardError::InvalidInput {
            reason: "execution revocation reason must contain 1..=1024 UTF-8 bytes without surrounding whitespace or control characters".to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_records(
    records: &BTreeMap<String, ExecutionRevocation>,
) -> Result<(), TrustCardError> {
    if records.len() > MAX_EXECUTION_REVOCATIONS {
        return Err(TrustCardError::InvalidSnapshot(
            "execution revocation retention limit exceeded".to_string(),
        ));
    }
    for (key, record) in records {
        if record.validate().is_err() || key != &record.target.storage_key() {
            return Err(TrustCardError::InvalidSnapshot(
                "invalid execution revocation record or target binding".to_string(),
            ));
        }
    }
    Ok(())
}

/// Enforce retention against the current durable row, not only an in-memory
/// copy which may predate another writer's revocation.
pub(super) fn ensure_retained(
    current: &BTreeMap<String, ExecutionRevocation>,
    proposed: &BTreeMap<String, ExecutionRevocation>,
) -> Result<(), TrustCardError> {
    if current
        .iter()
        .any(|(key, record)| proposed.get(key) != Some(record))
    {
        return Err(TrustCardError::InvalidSnapshot(
            "execution revocations cannot be removed or rewritten".to_string(),
        ));
    }
    Ok(())
}

impl TrustCardRegistry {
    /// Add a permanent denial to the next signed snapshot. The caller must
    /// persist the registry before reporting durable success. Existing records
    /// are immutable and are never evicted to make room for another target.
    pub fn revoke_execution_authority(
        &mut self,
        target: ExecutionRevocationTarget,
        reason: &str,
        now_secs: u64,
    ) -> Result<ExecutionRevocation, TrustCardError> {
        target.validate()?;
        validate_reason(reason)?;
        let key = target.storage_key();
        if let Some(existing) = self.execution_revocations.get(&key) {
            return Ok(existing.clone());
        }
        if self.execution_revocations.len() >= MAX_EXECUTION_REVOCATIONS {
            return Err(TrustCardError::InvalidInput {
                reason: format!(
                    "execution revocation retention reached {MAX_EXECUTION_REVOCATIONS} records; earlier denials cannot be discarded"
                ),
            });
        }
        if self.snapshot_epoch == u64::MAX {
            return Err(TrustCardError::InvalidSnapshot(
                "execution revocation snapshot sequence exhausted".to_string(),
            ));
        }
        let record = ExecutionRevocation {
            target,
            revoked_at_secs: now_secs,
            reason: reason.to_string(),
        };
        self.advance_snapshot_sequence_for_mutation();
        self.execution_revocations.insert(key, record.clone());
        Ok(record)
    }

    /// Check the exact identity retained by publisher admission. This lookup
    /// performs no archive reads or name inference. Both kinds of denial apply
    /// to source-only and authority-bearing artifacts; the caller supplies a
    /// registry freshly loaded through the authenticated authoritative loader.
    pub fn execution_authority_revocation(
        &self,
        publisher_key_id: &str,
        artifact_sha256: &str,
    ) -> Result<Option<&ExecutionRevocation>, TrustCardError> {
        let publisher = ExecutionRevocationTarget::publisher_key(publisher_key_id)?;
        let artifact = ExecutionRevocationTarget::artifact_sha256(artifact_sha256)?;
        Ok(self
            .execution_revocations
            .get(&publisher.storage_key())
            .or_else(|| self.execution_revocations.get(&artifact.storage_key())))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ed25519_dalek::SigningKey;

    use super::super::{
        SnapshotSourceContext, TrustCardRegistrySnapshot, sign_snapshot_in_place, to_canonical_json,
    };
    use super::*;
    use crate::supply_chain::artifact_signing::KeyId;
    use crate::supply_chain::trust_card_registry_store::{SLOT_SNAPSHOT, TrustCardRegistryStore};

    const TEST_KEY: &[u8] = &[0x41; 32];

    fn publisher(seed: u8) -> String {
        KeyId::from_verifying_key(&SigningKey::from_bytes(&[seed; 32]).verifying_key()).to_string()
    }

    fn artifact(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn load(path: &Path) -> TrustCardRegistry {
        TrustCardRegistry::load_authoritative_state_with_key(
            path,
            TEST_KEY,
            60,
            20,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("load authenticated durable registry")
    }

    #[test]
    fn execution_revocations_match_exact_publisher_keys_and_artifact_bytes() {
        let mut registry = TrustCardRegistry::new(60, TEST_KEY);
        let key = publisher(1);
        let other_key = publisher(2);
        let denied_artifact = artifact(3);
        let allowed_artifact = artifact(4);
        assert!(
            registry
                .execution_authority_revocation(&key, &allowed_artifact)
                .unwrap()
                .is_none()
        );
        let content_denial = registry
            .revoke_execution_authority(
                ExecutionRevocationTarget::artifact_sha256(&denied_artifact).unwrap(),
                "compromised artifact",
                10,
            )
            .unwrap();
        for identity in [&key, &other_key] {
            assert_eq!(
                registry
                    .execution_authority_revocation(identity, &denied_artifact)
                    .unwrap(),
                Some(&content_denial)
            );
            assert!(
                registry
                    .execution_authority_revocation(identity, &allowed_artifact)
                    .unwrap()
                    .is_none()
            );
        }
        let publisher_denial = registry
            .revoke_execution_authority(
                ExecutionRevocationTarget::publisher_key(&key).unwrap(),
                "compromised publisher key",
                u64::MAX,
            )
            .unwrap();
        // A future audit timestamp never delays a permanent denial. A
        // publisher denial applies to every artifact admitted under that key.
        for digest in [&denied_artifact, &allowed_artifact] {
            assert_eq!(
                registry
                    .execution_authority_revocation(&key, digest)
                    .unwrap(),
                Some(&publisher_denial)
            );
        }
        assert!(
            registry
                .execution_authority_revocation(&other_key, &allowed_artifact)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn execution_revocation_rejects_aliases_partial_hashes_and_unbounded_reasons() {
        for id in [
            "",
            "publisher",
            "0123456789abcde",
            "0123456789abcdef0",
            "0123456789ABCDEf",
        ] {
            assert!(ExecutionRevocationTarget::publisher_key(id).is_err());
        }
        for digest in [
            "".to_string(),
            "sha256:01234567".to_string(),
            "ab".repeat(32),
            format!("sha256:{}", "AB".repeat(32)),
            format!("sha256:{}", "ab".repeat(33)),
        ] {
            assert!(ExecutionRevocationTarget::artifact_sha256(&digest).is_err());
        }
        let target = ExecutionRevocationTarget::publisher_key(&publisher(1)).unwrap();
        let mut registry = TrustCardRegistry::new(60, TEST_KEY);
        let before = registry.snapshot().unwrap();
        for reason in [
            "".to_string(),
            " leading".to_string(),
            "trailing ".to_string(),
            "line\nbreak".to_string(),
            "injected\0nul".to_string(),
            "é".repeat(MAX_REASON_BYTES / 2 + 1),
        ] {
            assert!(
                registry
                    .revoke_execution_authority(target.clone(), &reason, 10)
                    .is_err()
            );
            assert_eq!(registry.snapshot().unwrap(), before);
        }
        registry
            .revoke_execution_authority(target, &"é".repeat(MAX_REASON_BYTES / 2), 10)
            .expect("UTF-8 bytes at the inclusive bound are supported");
        assert!(
            registry
                .execution_authority_revocation("publisher", &artifact(1))
                .is_err()
        );
        assert!(
            registry
                .execution_authority_revocation(&publisher(1), "sha256:ab")
                .is_err()
        );
    }

    #[test]
    fn execution_revocation_repeats_preserve_first_record_and_snapshot_sequence() {
        let mut registry = TrustCardRegistry::new(60, TEST_KEY);
        let target = ExecutionRevocationTarget::publisher_key(&publisher(1)).unwrap();
        let first = registry
            .revoke_execution_authority(target.clone(), "first reason", 10)
            .unwrap();
        let before = registry.snapshot().unwrap();
        let repeated = registry
            .revoke_execution_authority(target, "later reason", 20)
            .unwrap();
        assert_eq!(repeated, first);
        assert_eq!(registry.snapshot().unwrap(), before);
    }

    #[test]
    fn execution_revocation_capacity_and_sequence_refusal_preserve_denials() {
        let mut registry = TrustCardRegistry::new(60, TEST_KEY);
        for index in 0..MAX_EXECUTION_REVOCATIONS {
            let target = ExecutionRevocationTarget::PublisherKey {
                key_id: format!("{index:016x}"),
            };
            registry.execution_revocations.insert(
                target.storage_key(),
                ExecutionRevocation {
                    target,
                    revoked_at_secs: 10,
                    reason: "retained denial".to_string(),
                },
            );
        }
        let before = registry.snapshot().unwrap();
        let error = registry
            .revoke_execution_authority(
                ExecutionRevocationTarget::artifact_sha256(&artifact(1)).unwrap(),
                "new denial",
                20,
            )
            .unwrap_err();
        assert!(error.to_string().contains("retention reached"));
        registry
            .revoke_execution_authority(
                ExecutionRevocationTarget::publisher_key("0000000000000000").unwrap(),
                "idempotent repeat at capacity",
                20,
            )
            .unwrap();
        assert_eq!(registry.snapshot().unwrap(), before);

        let mut exhausted = TrustCardRegistry::new(60, TEST_KEY);
        exhausted.snapshot_epoch = u64::MAX;
        let before = exhausted.snapshot().unwrap();
        assert!(
            exhausted
                .revoke_execution_authority(
                    ExecutionRevocationTarget::publisher_key(&publisher(1)).unwrap(),
                    "cannot advance",
                    10,
                )
                .unwrap_err()
                .to_string()
                .contains("sequence exhausted")
        );
        assert_eq!(exhausted.snapshot().unwrap(), before);
    }

    #[test]
    fn execution_revocation_snapshot_authentication_covers_every_record() {
        let mut registry = TrustCardRegistry::new(60, TEST_KEY);
        registry
            .revoke_execution_authority(
                ExecutionRevocationTarget::publisher_key(&publisher(1)).unwrap(),
                "publisher revoked",
                10,
            )
            .unwrap();
        let snapshot = registry.snapshot().unwrap();
        let restored = TrustCardRegistry::from_snapshot(snapshot.clone(), TEST_KEY, 20).unwrap();
        assert!(
            restored
                .execution_authority_revocation(&publisher(1), &artifact(1))
                .unwrap()
                .is_some()
        );
        let mut stripped = snapshot.clone();
        stripped.execution_revocations.clear();
        assert!(TrustCardRegistry::from_snapshot(stripped, TEST_KEY, 20).is_err());
        let mut altered = snapshot.clone();
        altered
            .execution_revocations
            .values_mut()
            .next()
            .unwrap()
            .reason = "replacement reason".to_string();
        assert!(TrustCardRegistry::from_snapshot(altered, TEST_KEY, 20).is_err());
        let mut unsigned = snapshot.clone();
        unsigned.registry_signature.clear();
        assert!(TrustCardRegistry::from_snapshot(unsigned, TEST_KEY, 20).is_err());
        assert!(TrustCardRegistry::from_snapshot(snapshot, &[0x42; 32], 20).is_err());
    }

    #[test]
    fn execution_revocation_snapshot_rejects_bad_target_bindings_before_signing() {
        let mut registry = TrustCardRegistry::new(60, TEST_KEY);
        registry
            .revoke_execution_authority(
                ExecutionRevocationTarget::publisher_key(&publisher(1)).unwrap(),
                "publisher revoked",
                10,
            )
            .unwrap();
        let original = registry.snapshot().unwrap();
        let mut renamed = original.clone();
        let (_, record) = renamed.execution_revocations.pop_first().unwrap();
        renamed
            .execution_revocations
            .insert("display-name".into(), record);
        assert!(sign_snapshot_in_place(&mut renamed, TEST_KEY).is_err());
        let mut invalid = original;
        invalid
            .execution_revocations
            .values_mut()
            .next()
            .unwrap()
            .target = ExecutionRevocationTarget::Artifact {
            sha256: "sha256:abcd".into(),
        };
        assert!(sign_snapshot_in_place(&mut invalid, TEST_KEY).is_err());
    }

    #[test]
    fn signed_legacy_empty_snapshots_keep_their_canonical_bytes() {
        let registry = TrustCardRegistry::new(60, TEST_KEY);
        let snapshot = registry.snapshot().unwrap();
        let encoded = to_canonical_json(&snapshot).unwrap();
        assert!(!encoded.contains("execution_revocations"));
        let decoded: TrustCardRegistrySnapshot = serde_json::from_str(&encoded).unwrap();
        assert!(decoded.execution_revocations.is_empty());
        assert_eq!(to_canonical_json(&decoded).unwrap(), encoded);
        TrustCardRegistry::from_snapshot(decoded.clone(), TEST_KEY, 20).unwrap();
        let mut unsigned = decoded;
        unsigned.registry_signature.clear();
        assert!(TrustCardRegistry::from_snapshot(unsigned, TEST_KEY, 20).is_err());
    }

    #[test]
    fn durable_execution_revocations_survive_reopen_and_reject_stale_writers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust.json");
        TrustCardRegistry::new(60, TEST_KEY)
            .persist_authoritative_state(&path)
            .unwrap();
        let mut current = load(&path);
        let mut stale = load(&path);
        let publisher_denial = current
            .revoke_execution_authority(
                ExecutionRevocationTarget::publisher_key(&publisher(1)).unwrap(),
                "first concurrent decision",
                10,
            )
            .unwrap();
        current.persist_authoritative_state(&path).unwrap();
        stale
            .revoke_execution_authority(
                ExecutionRevocationTarget::artifact_sha256(&artifact(2)).unwrap(),
                "second concurrent decision",
                11,
            )
            .unwrap();
        assert!(stale.persist_authoritative_state(&path).is_err());
        let mut reloaded = load(&path);
        assert_eq!(
            reloaded
                .execution_authority_revocation(&publisher(1), &artifact(1))
                .unwrap(),
            Some(&publisher_denial)
        );
        assert!(
            reloaded
                .execution_authority_revocation(&publisher(2), &artifact(2))
                .unwrap()
                .is_none()
        );
        reloaded
            .revoke_execution_authority(
                ExecutionRevocationTarget::artifact_sha256(&artifact(2)).unwrap(),
                "retry after reloading the authoritative head",
                12,
            )
            .unwrap();
        reloaded.persist_authoritative_state(&path).unwrap();
        let final_state = load(&path);
        assert_eq!(final_state.execution_revocations.len(), 2);
        assert_eq!(
            final_state
                .execution_authority_revocation(&publisher(1), &artifact(1))
                .unwrap(),
            Some(&publisher_denial)
        );
    }

    #[test]
    fn durable_execution_revocations_reject_signed_successor_removal_and_rewrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust.json");
        let mut registry = TrustCardRegistry::new(60, TEST_KEY);
        registry
            .revoke_execution_authority(
                ExecutionRevocationTarget::publisher_key(&publisher(1)).unwrap(),
                "permanent denial",
                10,
            )
            .unwrap();
        registry.persist_authoritative_state(&path).unwrap();
        let original = load(&path).snapshot().unwrap();
        for remove in [true, false] {
            let mut successor = original.clone();
            successor.snapshot_epoch += 1;
            successor.previous_snapshot_hash = Some(original.snapshot_hash.clone());
            if remove {
                successor.execution_revocations.clear();
            } else {
                successor
                    .execution_revocations
                    .values_mut()
                    .next()
                    .unwrap()
                    .revoked_at_secs += 1;
            }
            sign_snapshot_in_place(&mut successor, TEST_KEY).unwrap();
            let proposed = TrustCardRegistry::from_snapshot(successor, TEST_KEY, 20).unwrap();
            let error = proposed.persist_authoritative_state(&path).unwrap_err();
            assert!(error.to_string().contains("cannot be removed or rewritten"));
            assert_eq!(load(&path).snapshot().unwrap(), original);
        }
    }

    #[test]
    fn stale_legacy_import_cannot_replace_durable_execution_revocations() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy-trust.json");
        let legacy = TrustCardRegistry::new(60, TEST_KEY).snapshot().unwrap();
        std::fs::write(&path, to_canonical_json(&legacy).unwrap()).unwrap();
        let mut current = load(&path);
        let denial = current
            .revoke_execution_authority(
                ExecutionRevocationTarget::publisher_key(&publisher(1)).unwrap(),
                "new durable decision",
                10,
            )
            .unwrap();
        current.persist_authoritative_state(&path).unwrap();
        let imported = TrustCardRegistry::finish_legacy_import(
            &path,
            &legacy,
            TEST_KEY,
            60,
            20,
            SnapshotSourceContext::TrustedFile,
        )
        .unwrap();
        assert_eq!(
            imported
                .execution_authority_revocation(&publisher(1), &artifact(1))
                .unwrap(),
            Some(&denial)
        );
    }

    #[test]
    fn malformed_durable_revocations_are_not_overwritten_by_an_old_writer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust.json");
        let mut registry = TrustCardRegistry::new(60, TEST_KEY);
        registry
            .revoke_execution_authority(
                ExecutionRevocationTarget::publisher_key(&publisher(1)).unwrap(),
                "retained decision",
                10,
            )
            .unwrap();
        registry.persist_authoritative_state(&path).unwrap();
        let store = TrustCardRegistryStore::open(&path).unwrap();
        let mut tampered = load(&path).snapshot().unwrap();
        tampered.execution_revocations.clear();
        store
            .overwrite_slot_for_tests(SLOT_SNAPSHOT, &to_canonical_json(&tampered).unwrap())
            .unwrap();
        registry
            .revoke_execution_authority(
                ExecutionRevocationTarget::artifact_sha256(&artifact(2)).unwrap(),
                "later decision",
                20,
            )
            .unwrap();
        assert!(registry.persist_authoritative_state(&path).is_err());
        assert!(
            TrustCardRegistry::load_authoritative_state_with_key(
                &path,
                TEST_KEY,
                60,
                30,
                SnapshotSourceContext::TrustedFile,
            )
            .is_err()
        );
    }

    #[test]
    fn a_rolled_back_signed_row_cannot_supply_the_retention_baseline() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust.json");
        let mut registry = TrustCardRegistry::new(60, TEST_KEY);
        let old_signed = registry.snapshot().unwrap();
        registry.persist_authoritative_state(&path).unwrap();
        registry
            .revoke_execution_authority(
                ExecutionRevocationTarget::publisher_key(&publisher(1)).unwrap(),
                "retained decision",
                10,
            )
            .unwrap();
        registry.persist_authoritative_state(&path).unwrap();
        let store = TrustCardRegistryStore::open(&path).unwrap();
        store
            .overwrite_slot_for_tests(SLOT_SNAPSHOT, &to_canonical_json(&old_signed).unwrap())
            .unwrap();
        registry
            .revoke_execution_authority(
                ExecutionRevocationTarget::artifact_sha256(&artifact(2)).unwrap(),
                "later decision",
                20,
            )
            .unwrap();
        let error = registry.persist_authoritative_state(&path).unwrap_err();
        assert!(error.to_string().contains("snapshot rollback rejected"));
        let (retained_raw, _) = store.load_state().unwrap().unwrap();
        assert_eq!(retained_raw, to_canonical_json(&old_signed).unwrap());
    }
}
