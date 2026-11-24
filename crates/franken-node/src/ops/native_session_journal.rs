//! Durable supervisor observations at the real host-I/O provider boundary.
//!
//! The worker may enter a provider only after the supervisor synchronizes its
//! signed admission record. A return marker records only that the provider
//! returned, not an external commit, terminal session, or complete history.
//! Journals are never resumed: a failed append poisons this launch's writer and
//! a crash may leave an incomplete suffix after an authenticated prefix.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub(crate) const NATIVE_SESSION_EFFECT_JOURNAL_DIRECTORY: &str = "session-effect-journals";
pub(crate) const NATIVE_SESSION_EFFECT_JOURNAL_SCHEMA: &str =
    "franken-node/native-effect-journal-record/v1";
pub(crate) const NATIVE_SESSION_EFFECT_JOURNAL_EVENT_CAP: usize = 2048;
pub(crate) const NATIVE_SESSION_EFFECT_JOURNAL_BYTE_CAP: usize = 4 * 1024 * 1024;
pub(crate) const NATIVE_SESSION_EFFECT_JOURNAL_RECORD_CAP: usize = 4096;
const EVENT_METADATA_CAP: usize = 1024;
const SIGNATURE_DOMAIN: &[u8] = b"franken-node/native-effect-journal-signature/v1\0";
const RECORD_HASH_DOMAIN: &[u8] = b"franken-node/native-effect-journal-record/v1\0";

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelope {
    payload_json: String,
    signature_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalPayload<'a> {
    schema_version: &'a str,
    session_nonce: &'a str,
    product_root_key_id: &'a str,
    admission_sha256: &'a str,
    event_index: u64,
    previous_record_sha256: &'a str,
    event: JournalEvent<'a>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum JournalEvent<'a> {
    Header {
        scope: &'a str,
        event_cap: usize,
        byte_cap: usize,
    },
    Admitted {
        sequence: u64,
        effect_kind: &'a str,
        request_hash: &'a str,
    },
    ProviderReturned {
        sequence: u64,
    },
}

struct EncodedRecord {
    line: Vec<u8>,
    hash: String,
}

/// One launch's append-only obligation. No SQLite connection or worker-owned
/// signing authority crosses into the journal reader thread.
pub(crate) struct NativeSessionEffectJournalWriter {
    file: File,
    path: PathBuf,
    signing_key: SigningKey,
    session_nonce: String,
    product_root_key_id: String,
    admission_sha256: String,
    previous_record_sha256: String,
    next_record_index: u64,
    next_sequence: u64,
    pending_sequence: Option<u64>,
    event_count: usize,
    byte_count: usize,
    failed: Option<String>,
}

impl std::fmt::Debug for NativeSessionEffectJournalWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeSessionEffectJournalWriter")
            .field("event_count", &self.event_count)
            .field("byte_count", &self.byte_count)
            .field("poisoned", &self.failed.is_some())
            .finish_non_exhaustive()
    }
}

pub(crate) fn native_session_effect_journal_path(root: &Path, nonce: &str) -> PathBuf {
    root.join(NATIVE_SESSION_EFFECT_JOURNAL_DIRECTORY)
        .join(format!(
            "{}.jsonl",
            hex::encode(Sha256::digest(nonce.as_bytes()))
        ))
}

fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "inspect native-session journal directory {}",
            path.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("native-session journal requires a private non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!("native-session journal directory must be private and owned");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x0000_0400 != 0 {
            bail!("native-session journal directory must not be a reparse point");
        }
    }
    Ok(())
}

fn create_private_journal_directory(root: &Path) -> Result<(PathBuf, bool)> {
    validate_private_directory(root)?;
    let directory = root.join(NATIVE_SESSION_EFFECT_JOURNAL_DIRECTORY);
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    let created = match builder.create(&directory) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error).context("create private native-session journal directory"),
    };
    validate_private_directory(&directory)?;
    Ok((directory, created))
}

fn create_private_journal_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.append(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(0x0020_0000).share_mode(0x0000_0001);
    }
    let file = options
        .open(path)
        .context("create new native-session journal; existing journals cannot be resumed")?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("native-session journal is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!("native-session journal file must be private, owned, and single-linked");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x0000_0400 != 0 {
            bail!("native-session journal file must not be a reparse point");
        }
    }
    Ok(file)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl NativeSessionEffectJournalWriter {
    /// The inventory guard supplies an already authenticated admission and its
    /// existing product root. This constructor never loads or creates keys.
    pub(crate) fn create(
        protected_root: &Path,
        session_nonce: &str,
        product_root_key_id: &str,
        admission_sha256: &str,
        signing_key: SigningKey,
    ) -> Result<Self> {
        let nonce =
            uuid::Uuid::parse_str(session_nonce).context("invalid journal session nonce")?;
        if nonce.is_nil() || nonce.to_string() != session_nonce {
            bail!("journal session nonce must be a canonical non-nil UUID");
        }
        if product_root_key_id
            != format!(
                "ed25519:{}",
                hex::encode(signing_key.verifying_key().as_bytes())
            )
            || !valid_digest(admission_sha256)
        {
            bail!("native-session journal authority does not match its admission");
        }
        let (directory, created_directory) = create_private_journal_directory(protected_root)?;
        let path = native_session_effect_journal_path(protected_root, session_nonce);
        let file = create_private_journal_file(&path)?;
        let mut writer = Self {
            file,
            path,
            signing_key,
            session_nonce: session_nonce.to_owned(),
            product_root_key_id: product_root_key_id.to_owned(),
            admission_sha256: admission_sha256.to_owned(),
            previous_record_sha256: "0".repeat(64),
            next_record_index: 0,
            next_sequence: 0,
            pending_sequence: None,
            event_count: 0,
            byte_count: 0,
            failed: None,
        };
        let header = writer.encode_record(
            0,
            &writer.previous_record_sha256,
            JournalEvent::Header {
                scope: "host_io_provider_calls",
                event_cap: NATIVE_SESSION_EFFECT_JOURNAL_EVENT_CAP,
                byte_cap: NATIVE_SESSION_EFFECT_JOURNAL_BYTE_CAP,
            },
        )?;
        writer.append_record(header)?;
        // The header, newly published file, and any newly created directory
        // must all survive before this writer can authorize any provider call.
        #[cfg(unix)]
        {
            File::open(&directory)?.sync_all()?;
            if created_directory {
                File::open(protected_root)?.sync_all()?;
            }
        }
        #[cfg(not(unix))]
        let _ = (&directory, created_directory);
        Ok(writer)
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }

    fn ensure_healthy(&self) -> Result<()> {
        if let Some(error) = &self.failed {
            bail!("native-session journal writer is poisoned: {error}");
        }
        Ok(())
    }

    fn poison<T>(&mut self, result: Result<T>) -> Result<T> {
        if let Err(error) = &result
            && self.failed.is_none()
        {
            self.failed = Some(format!("{error:#}"));
        }
        result
    }

    fn encode_record(
        &self,
        event_index: u64,
        previous_record_sha256: &str,
        event: JournalEvent<'_>,
    ) -> Result<EncodedRecord> {
        if serde_json::to_vec(&event)?.len() > EVENT_METADATA_CAP {
            bail!("native-session journal event metadata exceeds its byte cap");
        }
        let payload_json = serde_json::to_string(&JournalPayload {
            schema_version: NATIVE_SESSION_EFFECT_JOURNAL_SCHEMA,
            session_nonce: &self.session_nonce,
            product_root_key_id: &self.product_root_key_id,
            admission_sha256: &self.admission_sha256,
            event_index,
            previous_record_sha256,
            event,
        })?;
        let mut preimage = SIGNATURE_DOMAIN.to_vec();
        preimage.extend_from_slice(&u64::try_from(payload_json.len())?.to_be_bytes());
        preimage.extend_from_slice(payload_json.as_bytes());
        let signature_hex = hex::encode(self.signing_key.sign(&preimage).to_bytes());
        let mut line = serde_json::to_vec(&JournalEnvelope {
            payload_json,
            signature_hex,
        })?;
        if line.len() > NATIVE_SESSION_EFFECT_JOURNAL_RECORD_CAP {
            bail!("native-session journal record exceeds its byte cap");
        }
        let mut hash = Sha256::new();
        hash.update(RECORD_HASH_DOMAIN);
        hash.update(u64::try_from(line.len())?.to_be_bytes());
        hash.update(&line);
        let hash = hex::encode(hash.finalize());
        line.push(b'\n');
        Ok(EncodedRecord { line, hash })
    }

    fn append_record(&mut self, record: EncodedRecord) -> Result<()> {
        let new_bytes = self
            .byte_count
            .checked_add(record.line.len())
            .context("native-session journal byte count overflowed")?;
        if new_bytes > NATIVE_SESSION_EFFECT_JOURNAL_BYTE_CAP {
            bail!("native-session journal reached its byte cap");
        }
        self.file.write_all(&record.line).with_context(|| {
            format!(
                "append native-session journal record {}",
                self.path.display()
            )
        })?;
        self.file
            .sync_all()
            .context("synchronize native-session journal record before acknowledgement")?;
        self.byte_count = new_bytes;
        self.previous_record_sha256 = record.hash;
        self.next_record_index = self
            .next_record_index
            .checked_add(1)
            .context("native-session journal record index overflowed")?;
        Ok(())
    }

    /// Success is the only point at which a supervisor may acknowledge this
    /// exact admission. Every failure is permanent for this launch's writer.
    pub(crate) fn admit(
        &mut self,
        sequence: u64,
        effect_kind: &str,
        request_hash: &str,
    ) -> Result<()> {
        self.ensure_healthy()?;
        let result = self.admit_inner(sequence, effect_kind, request_hash);
        self.poison(result)
    }

    fn admit_inner(&mut self, sequence: u64, effect_kind: &str, request_hash: &str) -> Result<()> {
        if self.pending_sequence.is_some() || sequence != self.next_sequence {
            bail!("native-session journal admission is out of order or has an outstanding call");
        }
        if effect_kind.trim().is_empty()
            || !request_hash
                .strip_prefix("sha256:")
                .is_some_and(valid_digest)
        {
            bail!("native-session journal admission metadata is invalid");
        }
        if self.event_count.saturating_add(2) > NATIVE_SESSION_EFFECT_JOURNAL_EVENT_CAP {
            bail!(
                "native-session journal cannot reserve admission and return within its event cap"
            );
        }
        let admission = self.encode_record(
            self.next_record_index,
            &self.previous_record_sha256,
            JournalEvent::Admitted {
                sequence,
                effect_kind,
                request_hash,
            },
        )?;
        // Reserve the maximum return envelope and its newline without signing
        // a return that has not happened. Its actual record is signed only
        // after the supervisor observes the matching provider-return frame.
        let reserved = self
            .byte_count
            .checked_add(admission.line.len())
            .and_then(|bytes| bytes.checked_add(NATIVE_SESSION_EFFECT_JOURNAL_RECORD_CAP + 1))
            .context("native-session journal pair reservation overflowed")?;
        if reserved > NATIVE_SESSION_EFFECT_JOURNAL_BYTE_CAP {
            bail!("native-session journal cannot reserve admission and return within its byte cap");
        }
        self.append_record(admission)?;
        self.event_count += 1;
        self.pending_sequence = Some(sequence);
        self.next_sequence = sequence
            .checked_add(1)
            .context("journal sequence overflowed")?;
        Ok(())
    }

    pub(crate) fn complete(&mut self, sequence: u64) -> Result<()> {
        self.ensure_healthy()?;
        let result = self.complete_inner(sequence);
        self.poison(result)
    }

    fn complete_inner(&mut self, sequence: u64) -> Result<()> {
        if self.pending_sequence != Some(sequence) {
            bail!("native-session journal return does not match its outstanding admission");
        }
        let record = self.encode_record(
            self.next_record_index,
            &self.previous_record_sha256,
            JournalEvent::ProviderReturned { sequence },
        )?;
        self.append_record(record)?;
        self.event_count += 1;
        self.pending_sequence = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    const NONCE: &str = "0193f780-3b1d-7a80-a4b0-d1e6578c9097";

    fn writer(root: &Path) -> NativeSessionEffectJournalWriter {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = SigningKey::from_bytes(&[93; 32]);
        let id = format!("ed25519:{}", hex::encode(key.verifying_key().as_bytes()));
        NativeSessionEffectJournalWriter::create(root, NONCE, &id, &"ab".repeat(32), key).unwrap()
    }

    fn request_hash() -> String {
        format!("sha256:{}", "cd".repeat(32))
    }

    // Independently exercise the documented raw-byte signature and link
    // contract, rather than reconstructing payloads with the producer types.
    fn authenticate_lines(bytes: &[u8], key: &VerifyingKey) -> Vec<serde_json::Value> {
        assert_eq!(bytes.last(), Some(&b'\n'));
        let mut previous = "0".repeat(64);
        let mut payloads = Vec::new();
        for (index, line) in bytes[..bytes.len() - 1]
            .split(|byte| *byte == b'\n')
            .enumerate()
        {
            let envelope: serde_json::Value = serde_json::from_slice(line).unwrap();
            let raw = envelope["payload_json"].as_str().unwrap();
            let mut signature_input = b"franken-node/native-effect-journal-signature/v1\0".to_vec();
            signature_input.extend_from_slice(&(raw.len() as u64).to_be_bytes());
            signature_input.extend_from_slice(raw.as_bytes());
            let signature = Signature::from_slice(
                &hex::decode(envelope["signature_hex"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            key.verify_strict(&signature_input, &signature).unwrap();
            let payload: serde_json::Value = serde_json::from_str(raw).unwrap();
            assert_eq!(
                payload["schema_version"],
                "franken-node/native-effect-journal-record/v1"
            );
            assert_eq!(payload["event_index"], index as u64);
            assert_eq!(payload["previous_record_sha256"], previous);
            assert_eq!(payload["session_nonce"], NONCE);
            assert_eq!(payload["admission_sha256"], "ab".repeat(32));
            let mut hash = Sha256::new();
            hash.update(b"franken-node/native-effect-journal-record/v1\0");
            hash.update((line.len() as u64).to_be_bytes());
            hash.update(line);
            previous = hex::encode(hash.finalize());
            payloads.push(payload);
        }
        payloads
    }

    #[test]
    fn journal_publishes_authenticated_header_and_synchronized_provider_prefix() {
        fn assert_send<T: Send>() {}
        assert_send::<NativeSessionEffectJournalWriter>();
        let temp = tempfile::tempdir().unwrap();
        let mut journal = writer(temp.path());
        let key = journal.signing_key.verifying_key();
        let header = authenticate_lines(&std::fs::read(journal.path()).unwrap(), &key);
        assert_eq!(header.len(), 1);
        assert_eq!(
            header[0]["event"],
            serde_json::json!({
                "kind": "header", "scope": "host_io_provider_calls", "event_cap": 2048, "byte_cap": 4194304
            })
        );
        journal.admit(0, "fs_write", &request_hash()).unwrap();
        let admitted = authenticate_lines(&std::fs::read(journal.path()).unwrap(), &key);
        assert_eq!(admitted.len(), 2);
        assert_eq!(admitted[1]["event"]["kind"], "admitted");
        assert_eq!(admitted[1]["event"]["request_hash"], request_hash());
        journal.complete(0).unwrap();
        journal
            .admit(1, "network_request", &request_hash())
            .unwrap();
        let path = journal.path().to_path_buf();
        drop(journal);
        let retained = authenticate_lines(&std::fs::read(&path).unwrap(), &key);
        assert_eq!(retained.len(), 4);
        assert_eq!(retained[2]["event"]["kind"], "provider_returned");
        assert_eq!(retained[3]["event"]["kind"], "admitted");
        assert_eq!(retained[3]["event"]["sequence"], 1);
        assert!(
            retained
                .iter()
                .all(|payload| payload["event"]["kind"] != "terminal")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }

    #[test]
    fn journal_refuses_reuse_and_invalid_authority_without_overwriting_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let journal = writer(temp.path());
        let path = journal.path().to_path_buf();
        let before = std::fs::read(&path).unwrap();
        drop(journal);
        let key = SigningKey::from_bytes(&[93; 32]);
        let id = format!("ed25519:{}", hex::encode(key.verifying_key().as_bytes()));
        assert!(
            NativeSessionEffectJournalWriter::create(
                temp.path(),
                NONCE,
                &id,
                &"ab".repeat(32),
                key.clone()
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        for nonce in [
            "../escape",
            "00000000-0000-0000-0000-000000000000",
            "0193F780-3b1d-7a80-a4b0-d1e6578c9097",
        ] {
            assert!(
                NativeSessionEffectJournalWriter::create(
                    temp.path(),
                    nonce,
                    &id,
                    &"ab".repeat(32),
                    key.clone()
                )
                .is_err()
            );
        }
        assert!(
            NativeSessionEffectJournalWriter::create(
                temp.path(),
                NONCE,
                "ed25519:wrong",
                &"ab".repeat(32),
                key
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn journal_order_and_metadata_errors_permanently_poison_the_writer() {
        for mutation in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let mut journal = writer(temp.path());
            let before = std::fs::read(journal.path()).unwrap();
            let result = match mutation {
                0 => journal.admit(1, "fs_write", &request_hash()),
                1 => journal.complete(0),
                2 => journal.admit(0, " ", &request_hash()),
                3 => journal.admit(0, "fs_write", "sha256:invalid"),
                4 => journal.admit(0, &"x".repeat(1024), &request_hash()),
                _ => unreachable!(),
            };
            assert!(result.is_err());
            assert!(
                journal
                    .admit(0, "fs_write", &request_hash())
                    .unwrap_err()
                    .to_string()
                    .contains("poisoned")
            );
            assert_eq!(std::fs::read(journal.path()).unwrap(), before);
        }
        let temp = tempfile::tempdir().unwrap();
        let mut journal = writer(temp.path());
        journal.admit(0, "fs_read", &request_hash()).unwrap();
        let before = std::fs::read(journal.path()).unwrap();
        assert!(journal.admit(1, "fs_read", &request_hash()).is_err());
        assert!(journal.complete(0).is_err());
        assert_eq!(std::fs::read(journal.path()).unwrap(), before);
    }

    #[test]
    fn journal_reserves_the_return_before_admitting_at_event_and_byte_limits() {
        for byte_limit in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let mut journal = writer(temp.path());
            if byte_limit {
                journal.byte_count = NATIVE_SESSION_EFFECT_JOURNAL_BYTE_CAP - 1;
            } else {
                journal.event_count = NATIVE_SESSION_EFFECT_JOURNAL_EVENT_CAP - 1;
            }
            let before = std::fs::read(journal.path()).unwrap();
            assert!(journal.admit(0, "fs_write", &request_hash()).is_err());
            assert_eq!(std::fs::read(journal.path()).unwrap(), before);
            assert!(journal.failed.is_some());
        }
        let temp = tempfile::tempdir().unwrap();
        let mut journal = writer(temp.path());
        journal.event_count = NATIVE_SESSION_EFFECT_JOURNAL_EVENT_CAP - 2;
        journal.admit(0, "fs_write", &request_hash()).unwrap();
        journal.complete(0).unwrap();
        assert_eq!(journal.event_count, NATIVE_SESSION_EFFECT_JOURNAL_EVENT_CAP);
        assert!(journal.admit(1, "fs_write", &request_hash()).is_err());
    }

    #[test]
    fn journal_append_failure_cannot_be_cleared_by_replacing_the_file_handle() {
        let temp = tempfile::tempdir().unwrap();
        let mut journal = writer(temp.path());
        let path = journal.path().to_path_buf();
        let before = std::fs::read(&path).unwrap();
        journal.file = File::open(&path).unwrap();
        assert!(journal.admit(0, "fs_write", &request_hash()).is_err());
        journal.file = OpenOptions::new().append(true).open(&path).unwrap();
        assert!(
            journal
                .admit(0, "fs_write", &request_hash())
                .unwrap_err()
                .to_string()
                .contains("poisoned")
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn journal_sync_failure_poison_and_unsafe_directory_refusal() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let temp = tempfile::tempdir().unwrap();
        let mut journal = writer(temp.path());
        // /dev/null accepts writes but rejects fsync. This exercises a real
        // synchronization failure after write_all succeeded, without a mock.
        journal.file = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let error = journal.admit(0, "fs_write", &request_hash()).unwrap_err();
        assert!(format!("{error:#}").contains("synchronize"));
        assert!(
            journal
                .complete(0)
                .unwrap_err()
                .to_string()
                .contains("poisoned")
        );
        let key = SigningKey::from_bytes(&[93; 32]);
        let id = format!("ed25519:{}", hex::encode(key.verifying_key().as_bytes()));
        let alias = temp.path().join("root-alias");
        symlink(temp.path(), &alias).unwrap();
        assert!(
            NativeSessionEffectJournalWriter::create(
                &alias,
                NONCE,
                &id,
                &"ab".repeat(32),
                key.clone()
            )
            .is_err()
        );
        let directory = temp.path().join(NATIVE_SESSION_EFFECT_JOURNAL_DIRECTORY);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            NativeSessionEffectJournalWriter::create(
                temp.path(),
                NONCE,
                &id,
                &"ab".repeat(32),
                key
            )
            .is_err()
        );
        assert_eq!(
            std::fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}
