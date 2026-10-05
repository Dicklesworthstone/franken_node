//! Serialized, durable rollout intent storage. The project-wide advisory lock
//! is held across state transitions AND native source restoration. On Unix,
//! metadata is opened relative to pinned, no-follow directory descriptors.
//! Projects with an independently installed operator key require authenticated
//! state on every load and sign every durable revision. Existing projects remain
//! explicitly legacy until provisioned BEFORE rollout initialization.

use std::fs::File;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use rustix::fs::{Mode, OFlags, mkdirat, open, openat, renameat};
#[cfg(unix)]
use rustix::io::Errno;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use super::cohort::attestation::rollout_receipt as receipt;
#[cfg(unix)]
#[path = "rollout_store_signing.rs"]
mod signing;

const SIGNING_KEY_ENV: &str = "FRANKEN_NODE_ROLLOUT_SIGNING_KEY";
const EXPECTED_HEAD_ENV: &str = "FRANKEN_NODE_ROLLOUT_EXPECTED_HEAD_SHA256";

pub(super) const MAX_STATE_BYTES: usize = receipt::MAX_STATE_BYTES;

pub(super) struct Store {
    #[cfg(unix)]
    directory: File,
    #[cfg(not(unix))]
    directory: PathBuf,
    lock: File,
    #[cfg(unix)]
    signing: signing::Policy,
}

pub(super) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 160
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || matches!(name, "." | "..")
    {
        return Err(invalid("invalid rollout metadata filename"));
    }
    Ok(())
}

#[cfg(unix)]
fn child_directory(parent: &File, name: &str) -> io::Result<File> {
    match mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => parent.sync_all()?,
        Err(Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(File::from(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

impl Store {
    pub(super) fn open(project: &Path) -> io::Result<Self> {
        let selected = std::env::var_os(SIGNING_KEY_ENV).map(PathBuf::from);
        let expected = match std::env::var(EXPECTED_HEAD_ENV) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(error) => return Err(invalid(error.to_string())),
        };
        Self::open_with_key(project, selected.as_deref(), expected.as_deref())
    }

    fn open_with_key(project: &Path, selected: Option<&Path>, expected: Option<&str>) -> io::Result<Self> {
        #[cfg(unix)]
        let root = File::from(open(project,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty())?);
        #[cfg(unix)]
        let directory = {
            let config = child_directory(&root, ".franken-node")?;
            let state = child_directory(&config, "state")?;
            child_directory(&state, "rollout")?
        };
        #[cfg(not(unix))]
        let directory = {
            let path = project.join(".franken-node/state/rollout");
            std::fs::create_dir_all(&path)?;
            path
        };
        #[cfg(unix)]
        let lock = File::from(openat(
            &directory,
            "lock",
            OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        #[cfg(not(unix))]
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("lock"))?;
        let metadata = lock.metadata()?;
        if !metadata.is_file() {
            return Err(invalid("rollout lock must be a regular file"));
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            return Err(invalid("rollout lock must not have hardlink aliases"));
        }
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|error| {
            io::Error::new(error.kind(), format!("another rollout operation holds the project lock: {error}"))
        })?;
        #[cfg(unix)]
        let signing = signing::Policy::open(&root, project, selected, expected)?;
        #[cfg(not(unix))]
        if selected.is_some() || expected.is_some() || project.join(".franken-node/keys/migration-rollout.pub").symlink_metadata().is_ok() {
            return Err(invalid("operator-signed rollout storage is supported on Unix only"));
        }
        Ok(Self { directory, lock, #[cfg(unix)] signing })
    }

    pub(super) fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        #[cfg(unix)]
        self.signing.recheck()?;
        let raw = self.read_raw(name)?;
        #[cfg(unix)]
        self.signing.observe_head(name, raw.as_deref())?;
        raw.map(|raw| {
            #[cfg(unix)]
            { self.signing.decode(name, &raw) }
            #[cfg(not(unix))]
            { if raw.len() > MAX_STATE_BYTES { return Err(invalid("rollout state exceeds metadata byte budget")); }
              Ok(raw) }
        }).transpose()
    }

    fn read_raw(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        validate_name(name)?;
        #[cfg(unix)]
        let opened = openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ).map(File::from).map_err(io::Error::from);
        #[cfg(not(unix))]
        let opened = File::open(self.directory.join(name));
        let file = match opened {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > receipt::MAX_RECEIPT_BYTES as u64 {
            return Err(invalid("rollout state must be a bounded regular file"));
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            return Err(invalid("rollout state must not have hardlink aliases"));
        }
        let mut bytes = Vec::new();
        file.take(receipt::MAX_RECEIPT_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > receipt::MAX_RECEIPT_BYTES {
            return Err(invalid("rollout receipt exceeds metadata byte budget"));
        }
        Ok(Some(bytes))
    }

    pub(super) fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        validate_name(name)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(invalid("rollout state exceeds metadata byte budget"));
        }
        #[cfg(unix)]
        {
            let previous = self.read_raw(name)?;
            // Authenticate the predecessor even when the authority is absent:
            // removing a key must not silently turn a signed state into plain JSON.
            let decoded = previous.as_deref().map(|raw| self.signing.decode(name, raw)).transpose()?;
            self.signing.recheck()?;
            self.signing.observe_head(name, previous.as_deref())?;
            if self.signing.required() {
                if decoded.as_deref() == Some(bytes) { return Ok(()); }
                let sealed = self.signing.seal(name, bytes, previous.as_deref())?;
                // Archive before publishing the new head. A crash can leave an
                // unused signed receipt, never an unsigned or fabricated head.
                if let Some(previous) = previous {
                    self.archive(&previous)?;
                }
                self.archive(&sealed)?;
                self.signing.recheck()?;
                self.write_raw(name, &sealed)?;
                self.signing.published(name, &sealed);
                return Ok(());
            }
        }
        self.write_raw(name, bytes)
    }

    #[cfg(unix)]
    fn archive(&self, bytes: &[u8]) -> io::Result<()> {
        let name = receipt::receipt_name(&receipt::sha256(bytes)).map_err(|e| invalid(e.to_string()))?;
        let opened = openat(&self.directory, name.as_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600));
        match opened {
            Ok(fd) => {
                let mut file = File::from(fd);
                file.write_all(bytes)?;
                file.sync_all()?;
            }
            Err(Errno::EXIST) => {
                if self.read_raw(&name)?.as_deref() != Some(bytes) {
                    return Err(invalid("existing signed receipt differs; refusing to overwrite recovery evidence"));
                }
                let file = File::from(openat(&self.directory, name.as_str(),
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?);
                file.sync_all()?;
            }
            Err(error) => return Err(error.into()),
        }
        self.directory.sync_all()?;
        Ok(())
    }

    fn write_raw(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        validate_name(name)?;
        if bytes.len() > receipt::MAX_RECEIPT_BYTES {
            return Err(invalid("rollout receipt exceeds metadata byte budget"));
        }
        // Exclusive creation, not a shared truncating .tmp file. Failed writes
        // leave recovery material intact; no source or metadata cleanup occurs.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let clock = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let temp = format!(".rollout-{}-{clock}-{}.tmp", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
        #[cfg(unix)]
        let mut file = File::from(openat(
            &self.directory,
            temp.as_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        #[cfg(not(unix))]
        let mut file = OpenOptions::new().write(true).create_new(true).open(self.directory.join(&temp))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(unix)]
        {
            self.signing.recheck()?;
            renameat(&self.directory, temp.as_str(), &self.directory, name)?;
            // A completed write means the directory entry is durable too.
            self.directory.sync_all()?;
            self.signing.recheck()?;
        }
        #[cfg(not(unix))]
        std::fs::rename(self.directory.join(temp), self.directory.join(name))?;
        Ok(())
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // Release explicitly: a just-spawned child may briefly inherit the
        // open file description before close-on-exec takes effect.
        let _ = fs2::FileExt::unlock(&self.lock);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_project_lock_serializes_different_migration_ids() {
        let root = tempfile::tempdir().unwrap();
        let first = Store::open(root.path()).unwrap();
        assert!(Store::open(root.path()).is_err());
        first.write("mig-first.json", b"first").unwrap();
        drop(first);
        let second = Store::open(root.path()).unwrap();
        assert_eq!(second.read("mig-first.json").unwrap().unwrap(), b"first");
    }

    #[test]
    fn replacing_state_is_durable_bounded_and_does_not_follow_a_shared_temp_name() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(root.path()).unwrap();
        assert!(store.read("mig-state.json").unwrap().is_none());
        store.write("mig-state.json", b"old").unwrap();
        store.write("mig-state.json", b"new").unwrap();
        assert_eq!(store.read("mig-state.json").unwrap().unwrap(), b"new");
        assert!(store.write("mig-state.json", &vec![0; MAX_STATE_BYTES + 1]).is_err());
        assert_eq!(store.read("mig-state.json").unwrap().unwrap(), b"new");
        for name in ["../outside", "/absolute", "a/b", "..", "a\\b", "a\0b"] {
            assert!(store.write(name, b"bad").is_err());
            assert!(store.read(name).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn linked_metadata_directories_and_state_files_are_refused() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        symlink(external.path(), root.path().join(".franken-node")).unwrap();
        assert!(Store::open(root.path()).is_err());
        assert!(!external.path().join("state").exists());
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(root.path()).unwrap();
        let external = tempfile::NamedTempFile::new().unwrap();
        symlink(external.path(), root.path().join(".franken-node/state/rollout/mig-link.json")).unwrap();
        assert!(store.read("mig-link.json").is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "rollout_signing_tests.rs"]
mod signing_tests;
