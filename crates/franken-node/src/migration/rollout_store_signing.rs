//! Operator authority for rollout storage, pinned for the lifetime of its lock.
//! No authority is learned from state. No private key is stored in a project.

use super::{invalid, receipt};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rustix::fs::{Mode, OFlags, open, openat};
use std::cell::RefCell;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

const DIRECTORIES: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

// No Debug/Clone/Serialize: this value can hold a private signing key.
pub(super) struct Policy {
    root: File,
    project: String,
    trusted: Option<VerifyingKey>,
    signing: Option<SigningKey>,
    expected_head: Option<String>,
    observed_head: RefCell<Option<(String, Option<String>)>>,
}

fn error(error: impl std::fmt::Display) -> io::Error { invalid(error.to_string()) }

fn same_version(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino() && a.len() == b.len()
        && a.mode() == b.mode() && a.uid() == b.uid() && a.nlink() == b.nlink()
        && a.mtime() == b.mtime() && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime() && a.ctime_nsec() == b.ctime_nsec()
}

fn optional_anchor(root: &File) -> io::Result<Option<VerifyingKey>> {
    let mut directory = root.try_clone()?;
    for name in [".franken-node", "keys"] {
        directory = match openat(&directory, name, DIRECTORIES, Mode::empty()) {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    }
    let mut file = match openat(&directory, "migration-rollout.pub",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() > 66 {
        return Err(invalid("rollout authority must be a bounded unlinked regular public-key file"));
    }
    let mut bytes = Vec::new();
    file.by_ref().take(67).read_to_end(&mut bytes)?;
    if bytes.len() > 66 || !same_version(&before, &file.metadata()?) {
        return Err(invalid("rollout public key changed while reading"));
    }
    let text = std::str::from_utf8(&bytes).map_err(error)?;
    let text = text.strip_suffix("\r\n").or_else(|| text.strip_suffix('\n')).unwrap_or(text);
    receipt::public_key(text).map(Some).map_err(error)
}

fn secret(path: &Path, project: &Path) -> io::Result<SigningKey> {
    let normalized: PathBuf = path.components().collect();
    if !path.is_absolute() || normalized.as_os_str() != path.as_os_str()
        || path.starts_with(project)
        || !path.components().all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid("rollout signing key must be an absolute normalized path outside the project"));
    }
    // Open EVERY component without following links; a pathname alias cannot
    // redirect a seed read back into captured project inputs.
    let mut directory = File::from(open("/", DIRECTORIES, Mode::empty())?);
    let parent = path.parent().ok_or_else(|| invalid("rollout signing-key parent missing"))?;
    for part in parent.components() {
        if let Component::Normal(name) = part {
            directory = File::from(openat(&directory, name, DIRECTORIES, Mode::empty())?);
        }
    }
    let name = path.file_name().ok_or_else(|| invalid("rollout signing-key filename missing"))?;
    let mut file = File::from(openat(&directory, name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?);
    let before = file.metadata()?;
    if !before.is_file() || before.len() != 32 || before.nlink() != 1
        || before.mode() & 0o077 != 0 || before.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(invalid("rollout signing key must be an owner-only, owned, single-link regular 32-byte seed"));
    }
    let mut seed = Zeroizing::new([0_u8;32]);
    file.read_exact(seed.as_mut())?;
    let mut extra = [0;1];
    if file.read(&mut extra)? != 0 || !same_version(&before, &file.metadata()?) {
        return Err(invalid("rollout signing key changed while reading"));
    }
    Ok(SigningKey::from_bytes(&seed))
}

impl Policy {
    pub(super) fn open(root: &File, project: &Path, selected: Option<&Path>, expected_head: Option<&str>) -> io::Result<Self> {
        let trusted = optional_anchor(root)?;
        if let Some(pin) = expected_head { receipt::receipt_name(pin).map_err(error)?; }
        if (selected.is_some() || expected_head.is_some()) && trusted.is_none() {
            return Err(invalid("install the independent migration-rollout.pub operator key before selecting a signing key"));
        }
        let signing = selected.map(|path| secret(path, project)).transpose()?;
        if let Some(signing) = &signing
            && Some(signing.verifying_key()) != trusted
        {
            return Err(invalid("rollout signing key does not match the independently installed operator authority"));
        }
        let result = Self { root: root.try_clone()?,
            project: project.to_str().ok_or_else(|| invalid("rollout project path must be UTF-8"))?.into(),
            trusted, signing, expected_head: expected_head.map(str::to_owned),
            observed_head: RefCell::new(None) };
        result.recheck()?;
        Ok(result)
    }

    pub(super) fn required(&self) -> bool { self.trusted.is_some() }

    pub(super) fn recheck(&self) -> io::Result<()> {
        if optional_anchor(&self.root)? != self.trusted {
            return Err(invalid("rollout operator authority changed while the operation was locked"));
        }
        Ok(())
    }

    /// The independent checkpoint applies to the first state observed under
    /// this lock. Later writes must extend that observed head, including the
    /// intent -> completion pair, rather than reusing the original checkpoint.
    pub(super) fn observe_head(&self, name: &str, raw: Option<&[u8]>) -> io::Result<()> {
        if !self.required() { return Ok(()); }
        let hash = raw.map(receipt::sha256);
        let mut observed = self.observed_head.borrow_mut();
        match observed.as_ref() {
            Some((previous_name, previous_hash)) if previous_name != name || previous_hash != &hash =>
                return Err(invalid("signed rollout head changed after admission under the project lock")),
            Some(_) => {}
            None => {
                if let Some(expected) = &self.expected_head
                    && hash.as_ref() != Some(expected)
                {
                    return Err(invalid("rollout head differs from the independently retained checkpoint"));
                }
                *observed = Some((name.into(), hash));
            }
        }
        Ok(())
    }

    pub(super) fn published(&self, name: &str, raw: &[u8]) {
        *self.observed_head.borrow_mut() = Some((name.into(), Some(receipt::sha256(raw))));
    }

    pub(super) fn decode(&self, name: &str, raw: &[u8]) -> io::Result<Vec<u8>> {
        self.recheck()?;
        match &self.trusted {
            Some(trusted) => receipt::verify(raw, trusted, &self.project, name)
                .map(receipt::VerifiedReceipt::into_state).map_err(error),
            None => {
                // A missing anchor is not permission to downgrade an existing
                // signed state. The legacy path remains only for plain state.
                #[derive(serde::Deserialize)]
                struct Header { schema_version: String }
                if serde_json::from_slice::<Header>(raw).is_ok_and(|header| header.schema_version == receipt::SCHEMA) {
                    return Err(invalid("signed rollout state requires its independent operator public key"));
                }
                if raw.len() > receipt::MAX_STATE_BYTES {
                    return Err(invalid("rollout state exceeds metadata byte budget"));
                }
                Ok(raw.to_vec())
            }
        }
    }

    pub(super) fn seal(&self, name: &str, state: &[u8], previous: Option<&[u8]>) -> io::Result<Vec<u8>> {
        self.recheck()?;
        let signing = self.signing.as_ref().ok_or_else(|| invalid(
            "signed rollout writes require FRANKEN_NODE_ROLLOUT_SIGNING_KEY; no unsigned fallback is allowed"))?;
        receipt::seal(state, signing, &self.project, name, previous).map_err(error)
    }
}
