//! Bounded content-addressed store (CAS) — bd-f5b04.2.2.2 (TNR Phase 1 keystone).
//!
//! The CAS is the byte-backing store for Proof-Carrying Host Effects: an
//! [`crate::runtime`] effect receipt carries only *hashes* (pre/result/post
//! state), while the actual bytes (file contents, HTTP bodies, module-resolver
//! snapshots) live here, deduplicated by content hash. Deterministic replay
//! (`verify-replay`) serves recorded bytes back out of this store by hash and
//! asserts the re-derived hash matches.
//!
//! ## Design choices
//!
//! * **File-backed, not the SQLite adapter.** Blobs-as-files is the idiomatic
//!   franken_node storage pattern (mirrors `storage::cleanup_receipts`), is
//!   crash-safe via atomic rename, and avoids loading large blobs through a
//!   structured KV. The bead allowed either; file-backed is the better fit for
//!   opaque immutable blobs.
//! * **Content-addressed + immutable.** A blob's path is derived purely from
//!   its hash hex, so writes are idempotent (dedup) and there is no mutation
//!   surface. A crash mid-write leaves only an orphan `*.tmp` file (reclaimable
//!   via `prune_orphans`), never a torn blob.
//! * **Hardened.** Domain-separated + length-prefixed SHA-256 (collision
//!   resistance under a stable preimage), bounded reads (parser-bomb defence),
//!   per-blob + total-capacity caps with saturating arithmetic, read-time
//!   integrity verification with a constant-time hash compare, and hash-hex
//!   path validation so a caller-supplied hash can never escape the store root.
//!
//! Verification: `rch exec -- cargo test -p frankenengine-node
//! --no-default-features --test <shim> cas` (default build currently blocked by
//! unrelated sibling franken_engine compile breakage).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::security::constant_time::ct_eq;

/// Schema/format version for the on-disk CAS layout.
pub const CONTENT_ADDRESSED_STORE_SCHEMA: &str = crate::schema_versions::CONTENT_ADDRESSED_STORE;

/// Domain separator prefixing every content-hash preimage so a CAS hash can
/// never collide with a hash computed for another protocol context.
const CAS_HASH_DOMAIN: &[u8] = b"storage_cas_content_hash_v1:";

/// Algorithm tag embedded in every [`ContentHash`] string.
const HASH_ALGO_PREFIX: &str = "sha256:";

/// Default maximum size of a single blob (16 MiB). Rejects parser-bomb / OOM
/// inputs before they touch disk or are read back.
pub const DEFAULT_MAX_BLOB_BYTES: u64 = 16 * 1024 * 1024;

/// Default maximum number of distinct blobs the store will hold before `put`
/// fails closed. Prevents unbounded growth from a misbehaving producer.
pub const DEFAULT_MAX_ENTRIES: usize = 1_000_000;

/// Process-wide monotonic counter making each in-flight temp file name unique,
/// so two threads writing the *same* blob concurrently never share a temp path.
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Committed blobs are named with their 64-char hex digest (never start with a
/// dot); in-flight/orphan temp files are dotfiles ending in `.tmp`. This
/// predicate keeps `len()` counting only real blobs.
fn is_committed_blob(name: &std::ffi::OsStr) -> bool {
    !name.to_string_lossy().starts_with('.')
}

/// A content hash of the form `sha256:<64 hex chars>`. The only way to obtain a
/// well-formed value is [`content_hash`] or [`ContentHash::parse`], both of
/// which enforce the algorithm tag and a 64-char lowercase-hex digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash(String);

impl ContentHash {
    /// Parse and validate an externally-supplied hash string. Validation is
    /// what makes hash-derived filesystem paths safe (no traversal possible).
    pub fn parse(value: &str) -> Result<Self, CasError> {
        let hex = value
            .strip_prefix(HASH_ALGO_PREFIX)
            .ok_or_else(|| CasError::MalformedHash {
                value: value.to_string(),
            })?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CasError::MalformedHash {
                value: value.to_string(),
            });
        }
        // Normalize to lowercase so the path is canonical regardless of caller
        // casing; two spellings of the same digest must map to one blob.
        Ok(Self(format!(
            "{HASH_ALGO_PREFIX}{}",
            hex.to_ascii_lowercase()
        )))
    }

    /// The full `sha256:<hex>` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The 64-char hex digest (no algorithm prefix).
    fn hex(&self) -> &str {
        // Safe: every constructor guarantees the prefix is present.
        &self.0[HASH_ALGO_PREFIX.len()..]
    }
}

impl Serialize for ContentHash {
    /// Serializes as the plain `sha256:<hex>` string.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    /// Deserializes *with validation* via [`ContentHash::parse`], so a
    /// malformed or non-canonical hash can never enter through a wire payload.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        ContentHash::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Compute the content hash of `bytes` under the CAS domain separator with an
/// explicit length prefix (defeats prefix/extension and delimiter-collision
/// attacks on the preimage).
pub fn content_hash(bytes: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(CAS_HASH_DOMAIN);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
    ContentHash(format!(
        "{HASH_ALGO_PREFIX}{}",
        hex::encode(hasher.finalize())
    ))
}

/// Errors surfaced by the CAS. Every variant fails closed.
#[derive(Debug, thiserror::Error)]
pub enum CasError {
    #[error("content hash {value:?} is not a well-formed sha256:<hex> value")]
    MalformedHash { value: String },
    #[error("blob of {len} bytes exceeds the per-blob limit of {max} bytes")]
    BlobTooLarge { len: u64, max: u64 },
    #[error("store is at capacity ({max} entries); refusing new blob")]
    CapacityExceeded { max: usize },
    #[error("content {hash} is not present in the store")]
    NotFound { hash: String },
    #[error(
        "integrity violation: stored bytes for {hash} hash to {actual} (store corruption or tampering)"
    )]
    IntegrityViolation { hash: String, actual: String },
    #[error("filesystem error at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

fn io_err(path: &Path, source: std::io::Error) -> CasError {
    CasError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// A bounded, file-backed content-addressed store rooted at a directory.
#[derive(Debug, Clone)]
pub struct ContentAddressedStore {
    root: PathBuf,
    max_blob_bytes: u64,
    max_entries: usize,
}

impl ContentAddressedStore {
    /// Open (creating if needed) a store rooted at `root` with default limits.
    pub fn with_directory(root: impl Into<PathBuf>) -> Result<Self, CasError> {
        Self::with_limits(root, DEFAULT_MAX_BLOB_BYTES, DEFAULT_MAX_ENTRIES)
    }

    /// Open a store with explicit limits.
    pub fn with_limits(
        root: impl Into<PathBuf>,
        max_blob_bytes: u64,
        max_entries: usize,
    ) -> Result<Self, CasError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|source| io_err(&root, source))?;
        Ok(Self {
            root,
            max_blob_bytes,
            max_entries,
        })
    }

    /// Two-level sharded path for a hash: `<root>/<aa>/<full-hex>`. The hash is
    /// pre-validated (64 hex chars), so no path traversal is possible.
    fn blob_path(&self, hash: &ContentHash) -> PathBuf {
        let hex = hash.hex();
        self.root.join(&hex[..2]).join(hex)
    }

    /// Store `bytes`, returning its content hash. Idempotent: storing identical
    /// bytes twice writes once and yields the same hash (dedup). Fails closed
    /// if the blob exceeds the per-blob cap or the store is at capacity.
    pub fn put(&self, bytes: &[u8]) -> Result<ContentHash, CasError> {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if len > self.max_blob_bytes {
            return Err(CasError::BlobTooLarge {
                len,
                max: self.max_blob_bytes,
            });
        }
        let hash = content_hash(bytes);
        let path = self.blob_path(&hash);
        if path.exists() {
            // Dedup: identical content already stored. No capacity charge.
            return Ok(hash);
        }
        if self.len()? >= self.max_entries {
            return Err(CasError::CapacityExceeded {
                max: self.max_entries,
            });
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| io_err(parent, source))?;
        }
        self.write_atomic(&path, bytes)?;
        Ok(hash)
    }

    /// Retrieve the bytes for `hash`, verifying integrity on read. A bounded
    /// read defends against a blob that grew on disk beyond the per-blob cap;
    /// the recomputed hash is compared in constant time so a tampered or
    /// corrupted blob fails closed rather than returning bad bytes.
    pub fn get(&self, hash: &ContentHash) -> Result<Vec<u8>, CasError> {
        let path = self.blob_path(hash);
        if !path.exists() {
            return Err(CasError::NotFound {
                hash: hash.as_str().to_string(),
            });
        }
        // +1 so an over-cap blob surfaces as an integrity/size failure rather
        // than being silently truncated by the bounded reader.
        let limit = self.max_blob_bytes.saturating_add(1);
        let bytes = crate::bounded_read(&path, limit).map_err(|source| io_err(&path, source))?;
        let actual = content_hash(&bytes);
        if !ct_eq(actual.as_str(), hash.as_str()) {
            return Err(CasError::IntegrityViolation {
                hash: hash.as_str().to_string(),
                actual: actual.as_str().to_string(),
            });
        }
        Ok(bytes)
    }

    /// Whether `hash` is present (does not verify integrity; use [`get`] for
    /// that).
    pub fn contains(&self, hash: &ContentHash) -> bool {
        self.blob_path(hash).exists()
    }

    /// Number of distinct blobs currently stored.
    pub fn len(&self) -> Result<usize, CasError> {
        let mut count: usize = 0;
        let shards = match fs::read_dir(&self.root) {
            Ok(shards) => shards,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(source) => return Err(io_err(&self.root, source)),
        };
        for shard in shards {
            let shard = shard.map_err(|source| io_err(&self.root, source))?;
            if !shard
                .file_type()
                .map_err(|s| io_err(&shard.path(), s))?
                .is_dir()
            {
                continue;
            }
            let shard_path = shard.path();
            for blob in fs::read_dir(&shard_path).map_err(|s| io_err(&shard_path, s))? {
                let blob = blob.map_err(|s| io_err(&shard_path, s))?;
                if blob
                    .file_type()
                    .map_err(|s| io_err(&blob.path(), s))?
                    .is_file()
                    && is_committed_blob(&blob.file_name())
                {
                    count = count.saturating_add(1);
                }
            }
        }
        Ok(count)
    }

    /// Whether the store holds no blobs.
    pub fn is_empty(&self) -> Result<bool, CasError> {
        Ok(self.len()? == 0)
    }

    /// Remove any leftover `*.tmp` temp files from interrupted writes. Returns
    /// the count reclaimed. (Committed blobs are never removed.)
    pub fn prune_orphans(&self) -> Result<usize, CasError> {
        let mut removed: usize = 0;
        let shards = match fs::read_dir(&self.root) {
            Ok(shards) => shards,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(source) => return Err(io_err(&self.root, source)),
        };
        for shard in shards {
            let shard_path = shard.map_err(|s| io_err(&self.root, s))?.path();
            if !shard_path.is_dir() {
                continue;
            }
            for entry in fs::read_dir(&shard_path).map_err(|s| io_err(&shard_path, s))? {
                let entry_path = entry.map_err(|s| io_err(&shard_path, s))?.path();
                if entry_path.extension().is_some_and(|ext| ext == "tmp") {
                    fs::remove_file(&entry_path).map_err(|s| io_err(&entry_path, s))?;
                    removed = removed.saturating_add(1);
                }
            }
        }
        Ok(removed)
    }

    /// Atomic write: write to a unique temp file, fsync it, rename into place,
    /// then fsync the containing directory so the rename is durable. A crash at
    /// any point leaves either no file or the complete blob — never a torn one.
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), CasError> {
        let parent = path.parent().unwrap_or(&self.root);
        // Temp name is unique per (hash, pid, monotonic seq) so even two threads
        // in this process writing the *same* blob get distinct temp files; the
        // final rename is idempotent because the destination is content-addressed.
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "blob".to_string());
        let seq = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(".{file_name}.{}.{seq}.tmp", std::process::id()));

        let mut file = fs::File::create(&tmp).map_err(|s| io_err(&tmp, s))?;
        file.write_all(bytes).map_err(|s| io_err(&tmp, s))?;
        file.sync_all().map_err(|s| io_err(&tmp, s))?;
        drop(file);

        match fs::rename(&tmp, path) {
            Ok(()) => {}
            Err(source) => {
                // Clean the temp file on failure; ignore secondary cleanup error.
                let _ = fs::remove_file(&tmp);
                return Err(io_err(path, source));
            }
        }

        // Best-effort durability of the rename itself.
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, ContentAddressedStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cas = ContentAddressedStore::with_directory(dir.path()).expect("open cas");
        (dir, cas)
    }

    #[test]
    fn content_hash_is_deterministic_and_domain_separated() {
        let a = content_hash(b"hello world");
        let b = content_hash(b"hello world");
        assert_eq!(a, b, "same bytes must hash identically");
        assert!(a.as_str().starts_with("sha256:"));
        assert_eq!(a.hex().len(), 64);
        // Domain separation: our hash must not equal a bare sha256 of the bytes.
        let bare = {
            let mut h = Sha256::new();
            h.update(b"hello world");
            format!("sha256:{}", hex::encode(h.finalize()))
        };
        assert_ne!(
            a.as_str(),
            bare,
            "domain separator must change the preimage"
        );
    }

    #[test]
    fn put_get_round_trip() {
        let (_d, cas) = store();
        let bytes = b"the quick brown fox".to_vec();
        let hash = cas.put(&bytes).expect("put");
        assert!(cas.contains(&hash));
        assert_eq!(cas.get(&hash).expect("get"), bytes);
    }

    #[test]
    fn put_is_idempotent_dedup() {
        let (_d, cas) = store();
        let h1 = cas.put(b"dup").expect("put1");
        let h2 = cas.put(b"dup").expect("put2");
        assert_eq!(h1, h2);
        assert_eq!(cas.len().expect("len"), 1, "identical content stored once");
    }

    #[test]
    fn empty_bytes_round_trip() {
        let (_d, cas) = store();
        let h = cas.put(b"").expect("put empty");
        assert_eq!(cas.get(&h).expect("get empty"), Vec::<u8>::new());
    }

    #[test]
    fn get_missing_fails_closed() {
        let (_d, cas) = store();
        let h = content_hash(b"never stored");
        assert!(matches!(cas.get(&h), Err(CasError::NotFound { .. })));
    }

    #[test]
    fn oversize_blob_rejected_before_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cas = ContentAddressedStore::with_limits(dir.path(), 8, 100).expect("open");
        let err = cas
            .put(b"this is definitely more than eight bytes")
            .unwrap_err();
        assert!(matches!(err, CasError::BlobTooLarge { .. }));
        assert_eq!(cas.len().expect("len"), 0, "nothing written on rejection");
    }

    #[test]
    fn capacity_cap_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cas = ContentAddressedStore::with_limits(dir.path(), 1024, 2).expect("open");
        cas.put(b"a").expect("a");
        cas.put(b"b").expect("b");
        let err = cas.put(b"c").unwrap_err();
        assert!(matches!(err, CasError::CapacityExceeded { max: 2 }));
    }

    #[test]
    fn tampered_blob_fails_integrity_on_read() {
        let (_d, cas) = store();
        let hash = cas.put(b"trustworthy bytes").expect("put");
        // Corrupt the stored blob on disk behind the CAS's back.
        let path = cas.blob_path(&hash);
        fs::write(&path, b"tampered!").expect("overwrite");
        let err = cas.get(&hash).unwrap_err();
        assert!(
            matches!(err, CasError::IntegrityViolation { .. }),
            "tampered content must fail closed, got {err:?}"
        );
    }

    #[test]
    fn malformed_hash_is_rejected() {
        assert!(
            ContentHash::parse("deadbeef").is_err(),
            "missing algo prefix"
        );
        assert!(
            ContentHash::parse("sha256:xyz").is_err(),
            "non-hex / wrong length"
        );
        assert!(ContentHash::parse("sha256:zz").is_err(), "too short");
        let good = content_hash(b"x");
        assert_eq!(
            ContentHash::parse(good.as_str()).expect("parse good"),
            good,
            "round-trips a well-formed hash"
        );
    }

    #[test]
    fn parse_normalizes_uppercase_hex() {
        let lower = content_hash(b"normalize me");
        let upper = format!("sha256:{}", lower.hex().to_ascii_uppercase());
        assert_eq!(
            ContentHash::parse(&upper).expect("parse upper"),
            lower,
            "uppercase and lowercase hex map to the same blob"
        );
    }

    #[test]
    fn content_hash_serde_round_trips_and_validates() {
        let h = content_hash(b"serde me");
        let json = serde_json::to_string(&h).expect("serialize");
        assert_eq!(
            json,
            format!("\"{}\"", h.as_str()),
            "serializes as plain string"
        );
        let back: ContentHash = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, h);
        // A malformed hash must be rejected at deserialization, not silently accepted.
        assert!(
            serde_json::from_str::<ContentHash>("\"sha256:nothex\"").is_err(),
            "deserialize must validate via parse()"
        );
    }

    #[test]
    fn prune_orphans_removes_only_temp_files() {
        let (_d, cas) = store();
        let hash = cas.put(b"keep me").expect("put");
        // Simulate an interrupted write.
        let shard = cas.root.join(&hash.hex()[..2]);
        fs::create_dir_all(&shard).expect("shard");
        fs::write(shard.join(".orphan.123.tmp"), b"partial").expect("orphan");
        assert_eq!(cas.prune_orphans().expect("prune"), 1);
        assert!(cas.contains(&hash), "committed blob survives prune");
    }

    #[test]
    fn len_ignores_orphan_temp_files() {
        let (_d, cas) = store();
        let hash = cas.put(b"real blob").expect("put");
        assert_eq!(cas.len().expect("len"), 1);
        // An orphan temp file in the shard dir must NOT be counted as a blob —
        // otherwise the capacity check over-counts and `len()` lies.
        let shard = cas.root.join(&hash.hex()[..2]);
        fs::write(shard.join(".real-blob.999.0.tmp"), b"partial").expect("orphan");
        assert_eq!(
            cas.len().expect("len"),
            1,
            "temp/orphan files must not be counted toward stored-blob count"
        );
    }
}
