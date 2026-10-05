//! Serialized, durable rollout intent storage. The project-wide advisory lock
//! is held across state transitions AND native source restoration. On Unix,
//! metadata is opened relative to pinned, no-follow directory descriptors.
//! This coordinates cooperating operators; local state is not authenticated.

use std::fs::File;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use rustix::fs::{Mode, OFlags, mkdirat, open, openat, renameat};
#[cfg(unix)]
use rustix::io::Errno;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(not(unix))]
use std::path::PathBuf;

pub(super) const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;

pub(super) struct Store {
    #[cfg(unix)]
    directory: File,
    #[cfg(not(unix))]
    directory: PathBuf,
    lock: File,
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
        #[cfg(unix)]
        let directory = {
            let root = File::from(open(
                project,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
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
        Ok(Self { directory, lock })
    }

    pub(super) fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
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
        if !metadata.is_file() || metadata.len() > MAX_STATE_BYTES as u64 {
            return Err(invalid("rollout state must be a bounded regular file"));
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            return Err(invalid("rollout state must not have hardlink aliases"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_STATE_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(invalid("rollout state exceeds metadata byte budget"));
        }
        Ok(Some(bytes))
    }

    pub(super) fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        validate_name(name)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(invalid("rollout state exceeds metadata byte budget"));
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
            renameat(&self.directory, temp.as_str(), &self.directory, name)?;
            // A completed write means the directory entry is durable too.
            self.directory.sync_all()?;
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
