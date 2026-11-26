//! Local supervisor ownership for safe pending-session capacity recovery.
//!
//! A valid signature binds the immutable admission to one actual Unix inode.
//! The same descriptor stays locked until its supervisor finishes persisting
//! its outcome. An unlocked signed marker establishes only the absence of that
//! supervisor owner, never worker exit, effect completion, or quiescence.
//! Missing historical markers and unsupported platforms remain unproven.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

pub(super) const DIRECTORY: &str = "session-supervisor-leases";

/// Values already authenticated by the inventory's original admission receipt.
/// Kept separate from the public admission schema and portable evidence formats.
#[derive(Clone, Copy)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(super) struct Binding<'a> {
    pub session_nonce: &'a str,
    pub product_root_key_id: &'a str,
    pub admission_sha256: &'a str,
}

#[derive(Debug)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(super) struct SupervisorLease {
    _file: File,
}

#[cfg(unix)]
pub(super) struct StagedSupervisorLease {
    staged: tempfile::NamedTempFile,
    directory: PathBuf,
    lease_path: PathBuf,
    created_directory: bool,
}

#[cfg(not(unix))]
pub(super) struct StagedSupervisorLease;

#[derive(Debug)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(super) enum Probe {
    Live,
    Unproven,
    Orphaned(SupervisorLease),
}

pub(super) fn path(protected_root: &Path, nonce: &str) -> PathBuf {
    protected_root.join(DIRECTORY).join(format!(
        "{}.json",
        hex::encode(Sha256::digest(nonce.as_bytes()))
    ))
}

/// Stage, lock, sign, and `fsync` a supervisor ownership marker as an
/// unpublished private temp file inside `session-supervisor-leases/`.
///
/// The final `path(protected_root, nonce)` is NOT created until
/// [`StagedSupervisorLease::publish`] runs after uniqueness and capacity
/// checks succeed; dropping an unpublished handle unlinks the temp file and
/// leaves no ownership object behind. Because `persist_noclobber` atomically
/// links the same inode inside the same directory, the signed `(dev, ino)`
/// binding and held `flock` descriptor remain continuous across publication.
pub(super) fn stage(
    protected_root: &Path,
    binding: &Binding<'_>,
    signing_root: &SigningKey,
) -> Result<StagedSupervisorLease> {
    #[cfg(unix)]
    {
        unix::stage(protected_root, binding, signing_root)
    }
    #[cfg(not(unix))]
    {
        let _ = (protected_root, binding, signing_root);
        Ok(StagedSupervisorLease)
    }
}

impl StagedSupervisorLease {
    /// Atomically publish the already-locked, already-`fsync`ed lease marker
    /// at its final immutable path and durably sync its parent directory.
    pub(super) fn publish(self, protected_root: &Path) -> Result<Option<SupervisorLease>> {
        #[cfg(unix)]
        {
            unix::publish(self, protected_root).map(Some)
        }
        #[cfg(not(unix))]
        {
            let _ = (self, protected_root);
            Ok(None)
        }
    }
}

/// Called only after bounded immutable admission retention and before the DB
/// admission commits, with the inventory writer lock still held. A failed
/// publication is never resumed or overwritten.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn acquire(
    protected_root: &Path,
    binding: &Binding<'_>,
    signing_root: &SigningKey,
) -> Result<Option<SupervisorLease>> {
    #[cfg(unix)]
    {
        unix::acquire(protected_root, binding, signing_root).map(Some)
    }
    #[cfg(not(unix))]
    {
        // Preserve admission on platforms without this inode-bound protocol.
        // Their pending sessions cannot be finalized by guessing ownership.
        let _ = (protected_root, binding, signing_root);
        Ok(None)
    }
}

/// Take ownership nonblockingly before an operator finalizes a pending row.
/// The caller holds the inventory writer lock and must retain an acquired lease
/// through receipt publication and the corresponding database commit.
pub(super) fn probe(
    protected_root: &Path,
    binding: &Binding<'_>,
    trusted_root: &VerifyingKey,
) -> Result<Probe> {
    #[cfg(unix)]
    {
        unix::probe(protected_root, binding, trusted_root)
    }
    #[cfg(not(unix))]
    {
        let _ = (protected_root, binding, trusted_root);
        Ok(Probe::Unproven)
    }
}

#[cfg(unix)]
mod unix {
    use std::fs::{Metadata, OpenOptions, TryLockError};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    };

    use anyhow::{Context as _, bail};
    use ed25519_dalek::{Signature, Signer as _};
    use serde::{Deserialize, Serialize};

    use super::*;

    const SCHEMA: &str = "franken-node/native-session-supervisor-lease/v1";
    const SIGNATURE_DOMAIN: &[u8] = b"franken-node/native-session-supervisor-lease-signature/v1\0";
    const MAX_MARKER_BYTES: usize = 4096;

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Marker {
        schema_version: String,
        session_nonce: String,
        product_root_key_id: String,
        admission_sha256: String,
        device: u64,
        inode: u64,
        signature_hex: String,
    }

    impl Marker {
        fn preimage(&self) -> Result<Vec<u8>> {
            #[derive(Serialize)]
            struct Payload<'a> {
                schema_version: &'a str,
                session_nonce: &'a str,
                product_root_key_id: &'a str,
                admission_sha256: &'a str,
                device: u64,
                inode: u64,
            }
            let payload = serde_json::to_vec(&Payload {
                schema_version: &self.schema_version,
                session_nonce: &self.session_nonce,
                product_root_key_id: &self.product_root_key_id,
                admission_sha256: &self.admission_sha256,
                device: self.device,
                inode: self.inode,
            })?;
            let mut preimage = SIGNATURE_DOMAIN.to_vec();
            preimage.extend_from_slice(&u64::try_from(payload.len())?.to_be_bytes());
            preimage.extend_from_slice(&payload);
            Ok(preimage)
        }

        fn verify(
            &self,
            binding: &Binding<'_>,
            metadata: &Metadata,
            trusted_root: &VerifyingKey,
        ) -> Result<()> {
            if self.schema_version != SCHEMA
                || self.session_nonce != binding.session_nonce
                || self.product_root_key_id != binding.product_root_key_id
                || self.admission_sha256 != binding.admission_sha256
                || self.device != metadata.dev()
                || self.inode != metadata.ino()
                || self.signature_hex.len() != 128
                || !self
                    .signature_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!("native-session supervisor lease is not bound to this admission and file");
            }
            let signature = hex::decode(&self.signature_hex)
                .context("decode native-session supervisor lease signature")?;
            let signature = Signature::from_slice(&signature)
                .context("parse native-session supervisor lease signature")?;
            trusted_root
                .verify_strict(&self.preimage()?, &signature)
                .context("native-session supervisor lease signature is invalid")
        }
    }

    fn validate_binding(binding: &Binding<'_>, key: &VerifyingKey) -> Result<()> {
        let nonce = uuid::Uuid::parse_str(binding.session_nonce)
            .context("native-session supervisor lease nonce is invalid")?;
        if nonce.is_nil()
            || nonce.to_string() != binding.session_nonce
            || key.is_weak()
            || binding.product_root_key_id != format!("ed25519:{}", hex::encode(key.as_bytes()))
            || binding.admission_sha256.len() != 64
            || !binding
                .admission_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("native-session supervisor lease requires a canonical authenticated admission");
        }
        Ok(())
    }

    fn validate_directory(path: &Path) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)
            .context("inspect native-session supervisor lease directory")?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!(
                "native-session supervisor lease directory must be private, owned and nonsymlink"
            );
        }
        Ok(())
    }

    fn validate_root(protected_root: &Path) -> Result<()> {
        validate_directory(
            protected_root
                .parent()
                .context("native-session supervisor lease root has no parent")?,
        )?;
        validate_directory(protected_root)
    }

    fn validate_file(metadata: &Metadata) -> Result<()> {
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > MAX_MARKER_BYTES as u64
        {
            bail!("native-session supervisor lease must be a bounded private owned regular file");
        }
        Ok(())
    }

    fn flags() -> i32 {
        (rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOCTTY)
            .bits() as i32
    }

    fn validate_opened(path: &Path, file: &File) -> Result<Metadata> {
        let observed = std::fs::symlink_metadata(path)
            .context("inspect opened native-session supervisor lease")?;
        let opened = file
            .metadata()
            .context("inspect native-session supervisor lease descriptor")?;
        validate_file(&observed)?;
        validate_file(&opened)?;
        if observed.dev() != opened.dev() || observed.ino() != opened.ino() {
            bail!("native-session supervisor lease file changed while opening");
        }
        Ok(opened)
    }

    pub(super) fn stage(
        protected_root: &Path,
        binding: &Binding<'_>,
        signing_root: &SigningKey,
    ) -> Result<StagedSupervisorLease> {
        let trusted_root = signing_root.verifying_key();
        validate_binding(binding, &trusted_root)?;
        validate_root(protected_root)?;
        let directory = protected_root.join(DIRECTORY);
        let created_directory = match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => {
                return Err(error)
                    .context("create private native-session supervisor lease directory");
            }
        };
        validate_directory(&directory)?;
        let lease_path = path(protected_root, binding.session_nonce);
        let mut staged = tempfile::NamedTempFile::new_in(&directory)
            .context("stage immutable native-session supervisor lease")?;
        staged.as_file().try_lock().map_err(|error| {
            anyhow::anyhow!("staged native-session supervisor lease could not be locked: {error}")
        })?;
        let metadata = validate_opened(staged.path(), staged.as_file())?;
        let mut marker = Marker {
            schema_version: SCHEMA.to_owned(),
            session_nonce: binding.session_nonce.to_owned(),
            product_root_key_id: binding.product_root_key_id.to_owned(),
            admission_sha256: binding.admission_sha256.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            signature_hex: String::new(),
        };
        marker.signature_hex = hex::encode(signing_root.sign(&marker.preimage()?).to_bytes());
        marker.verify(binding, &metadata, &trusted_root)?;
        let bytes = serde_json::to_vec(&marker)?;
        if bytes.len() > MAX_MARKER_BYTES {
            bail!("native-session supervisor lease exceeds its marker byte bound");
        }
        staged
            .as_file_mut()
            .write_all(&bytes)
            .context("write staged native-session supervisor lease marker")?;
        staged
            .as_file()
            .sync_all()
            .context("sync staged native-session supervisor lease marker")?;
        Ok(StagedSupervisorLease {
            staged,
            directory,
            lease_path,
            created_directory,
        })
    }

    pub(super) fn publish(
        staged: StagedSupervisorLease,
        protected_root: &Path,
    ) -> Result<SupervisorLease> {
        let StagedSupervisorLease {
            staged,
            directory,
            lease_path,
            created_directory,
        } = staged;
        let file = staged.persist_noclobber(&lease_path).map_err(|error| {
            anyhow::anyhow!(
                "publish immutable native-session supervisor lease: {}",
                error.error
            )
        })?;
        validate_opened(&lease_path, &file)?;
        File::open(&directory)?.sync_all()?;
        if created_directory {
            File::open(protected_root)?.sync_all()?;
        }
        Ok(SupervisorLease { _file: file })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn acquire(
        protected_root: &Path,
        binding: &Binding<'_>,
        signing_root: &SigningKey,
    ) -> Result<SupervisorLease> {
        let trusted_root = signing_root.verifying_key();
        validate_binding(binding, &trusted_root)?;
        validate_root(protected_root)?;
        let directory = protected_root.join(DIRECTORY);
        let created_directory = match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => {
                return Err(error)
                    .context("create private native-session supervisor lease directory");
            }
        };
        validate_directory(&directory)?;
        let lease_path = path(protected_root, binding.session_nonce);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(flags())
            .open(&lease_path)
            .context("create immutable native-session supervisor lease")?;
        file.try_lock().map_err(|error| {
            anyhow::anyhow!("native-session supervisor lease could not be acquired: {error}")
        })?;
        let metadata = validate_opened(&lease_path, &file)?;
        let mut marker = Marker {
            schema_version: SCHEMA.to_owned(),
            session_nonce: binding.session_nonce.to_owned(),
            product_root_key_id: binding.product_root_key_id.to_owned(),
            admission_sha256: binding.admission_sha256.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            signature_hex: String::new(),
        };
        marker.signature_hex = hex::encode(signing_root.sign(&marker.preimage()?).to_bytes());
        marker.verify(binding, &metadata, &trusted_root)?;
        let bytes = serde_json::to_vec(&marker)?;
        if bytes.len() > MAX_MARKER_BYTES {
            bail!("native-session supervisor lease exceeds its marker byte bound");
        }
        file.write_all(&bytes)
            .context("write native-session supervisor lease marker")?;
        file.sync_all()
            .context("sync native-session supervisor lease marker")?;
        File::open(&directory)?.sync_all()?;
        if created_directory {
            File::open(protected_root)?.sync_all()?;
        }
        Ok(SupervisorLease { _file: file })
    }

    pub(super) fn probe(
        protected_root: &Path,
        binding: &Binding<'_>,
        trusted_root: &VerifyingKey,
    ) -> Result<Probe> {
        validate_binding(binding, trusted_root)?;
        validate_root(protected_root)?;
        let directory = protected_root.join(DIRECTORY);
        match std::fs::symlink_metadata(&directory) {
            Ok(_) => validate_directory(&directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Probe::Unproven);
            }
            Err(error) => {
                return Err(error).context("inspect retained native-session supervisor leases");
            }
        }
        let lease_path = path(protected_root, binding.session_nonce);
        match std::fs::symlink_metadata(&lease_path) {
            Ok(metadata) => validate_file(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Probe::Unproven);
            }
            Err(error) => {
                return Err(error).context("inspect retained native-session supervisor lease");
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(flags())
            .open(&lease_path)
            .context("open retained native-session supervisor lease")?;
        let metadata = validate_opened(&lease_path, &file)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Ok(Probe::Live),
            Err(TryLockError::Error(error)) => {
                return Err(error).context("native-session supervisor ownership is unavailable");
            }
        }
        let mut bytes = Vec::new();
        (&file)
            .take(MAX_MARKER_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .context("read retained native-session supervisor lease")?;
        if bytes.len() > MAX_MARKER_BYTES {
            bail!("native-session supervisor lease exceeds its marker byte bound");
        }
        let marker: Marker = serde_json::from_slice(&bytes)
            .context("decode retained native-session supervisor lease")?;
        marker.verify(binding, &metadata, trusted_root)?;
        // Recheck the path after taking the lock and reading the marker. A copied
        // or replaced marker cannot impersonate its still-locked original inode.
        validate_opened(&lease_path, &file)?;
        Ok(Probe::Orphaned(SupervisorLease { _file: file }))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Read as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::*;

    const NONCE: &str = "019a7f53-c180-7001-8001-000000000081";
    const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const CHILD_ROOT_ENV: &str = "FRANKEN_NODE_SUPERVISOR_LEASE_CHILD_ROOT";

    fn binding(root_id: &str) -> Binding<'_> {
        Binding {
            session_nonce: NONCE,
            product_root_key_id: root_id,
            admission_sha256: DIGEST,
        }
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, SigningKey, String) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let protected_root = temp.path().join("runtime-evidence");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&protected_root)
            .unwrap();
        let key = SigningKey::from_bytes(&[81; 32]);
        let root_id = format!("ed25519:{}", hex::encode(key.verifying_key().as_bytes()));
        (temp, protected_root, key, root_id)
    }

    fn copied_marker(path: &Path, bytes: &[u8]) {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
    }

    #[test]
    fn lease_is_exclusive_until_its_owner_releases_the_actual_descriptor() {
        let (_temp, root, key, root_id) = fixture();
        let binding = binding(&root_id);
        let owner = acquire(&root, &binding, &key).unwrap().unwrap();
        let bytes = std::fs::read(path(&root, NONCE)).unwrap();
        assert!(matches!(
            probe(&root, &binding, &key.verifying_key()).unwrap(),
            Probe::Live
        ));
        assert!(acquire(&root, &binding, &key).is_err());
        assert_eq!(std::fs::read(path(&root, NONCE)).unwrap(), bytes);
        drop(owner);
        let Probe::Orphaned(recovery_owner) = probe(&root, &binding, &key.verifying_key()).unwrap()
        else {
            panic!("released signed inode must be acquirable");
        };
        assert!(matches!(
            probe(&root, &binding, &key.verifying_key()).unwrap(),
            Probe::Live
        ));
        assert_eq!(std::fs::read(path(&root, NONCE)).unwrap(), bytes);
        drop(recovery_owner);
        assert!(matches!(
            probe(&root, &binding, &key.verifying_key()).unwrap(),
            Probe::Orphaned(_)
        ));
    }

    #[test]
    fn copied_or_replaced_marker_cannot_hide_a_live_supervisor() {
        let (_temp, root, key, root_id) = fixture();
        let binding = binding(&root_id);
        let _owner = acquire(&root, &binding, &key).unwrap().unwrap();
        let original = path(&root, NONCE);
        let retained = original.with_extension("retained");
        let bytes = std::fs::read(&original).unwrap();
        std::fs::rename(&original, &retained).unwrap();
        copied_marker(&original, &bytes);
        assert!(probe(&root, &binding, &key.verifying_key()).is_err());
        assert_eq!(std::fs::read(&retained).unwrap(), bytes);
        assert_eq!(std::fs::read(&original).unwrap(), bytes);
    }

    #[test]
    fn missing_invalid_and_foreign_lease_evidence_never_proves_orphanhood() {
        let (_temp, root, key, root_id) = fixture();
        let binding = binding(&root_id);
        assert!(matches!(
            probe(&root, &binding, &key.verifying_key()).unwrap(),
            Probe::Unproven
        ));
        assert!(!root.join(DIRECTORY).exists());
        let owner = acquire(&root, &binding, &key).unwrap().unwrap();
        drop(owner);
        let lease_path = path(&root, NONCE);
        let original = std::fs::read(&lease_path).unwrap();
        let wrong_digest = Binding {
            admission_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
            ..binding
        };
        assert!(probe(&root, &wrong_digest, &key.verifying_key()).is_err());
        let foreign_key = SigningKey::from_bytes(&[82; 32]);
        assert!(probe(&root, &binding, &foreign_key.verifying_key()).is_err());
        for invalid in [
            b"{}".to_vec(),
            br#"{"schema_version":"bad","schema_version":"bad"}"#.to_vec(),
            {
                let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
                value["signature_hex"] = serde_json::json!("00".repeat(64));
                serde_json::to_vec(&value).unwrap()
            },
            vec![b' '; 4097],
        ] {
            std::fs::write(&lease_path, invalid).unwrap();
            assert!(probe(&root, &binding, &key.verifying_key()).is_err());
        }
        std::fs::write(&lease_path, &original).unwrap();
        std::fs::set_permissions(&lease_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(probe(&root, &binding, &key.verifying_key()).is_err());
        std::fs::set_permissions(&lease_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&lease_path, lease_path.with_extension("retained")).unwrap();
        assert!(matches!(
            probe(&root, &binding, &key.verifying_key()).unwrap(),
            Probe::Unproven
        ));
        assert!(!lease_path.exists());
    }

    #[test]
    fn unsafe_lease_objects_are_refused_without_following_them() {
        use std::os::unix::fs::symlink;

        for kind in ["symlink", "hardlink", "directory"] {
            let (_temp, root, key, root_id) = fixture();
            let binding = binding(&root_id);
            drop(acquire(&root, &binding, &key).unwrap());
            let lease_path = path(&root, NONCE);
            let retained = lease_path.with_extension("retained");
            std::fs::rename(&lease_path, &retained).unwrap();
            let before = std::fs::read(&retained).unwrap();
            match kind {
                "symlink" => symlink(&retained, &lease_path).unwrap(),
                "hardlink" => std::fs::hard_link(&retained, &lease_path).unwrap(),
                "directory" => std::fs::create_dir(&lease_path).unwrap(),
                _ => unreachable!(),
            }
            assert!(probe(&root, &binding, &key.verifying_key()).is_err());
            assert_eq!(std::fs::read(&retained).unwrap(), before);
        }
    }

    struct ChildOwner(Child);

    impl Drop for ChildOwner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn lease_subprocess_owner() {
        let Some(root) = std::env::var_os(CHILD_ROOT_ENV) else {
            return;
        };
        let root = PathBuf::from(root);
        let key = SigningKey::from_bytes(&[81; 32]);
        let root_id = format!("ed25519:{}", hex::encode(key.verifying_key().as_bytes()));
        let _owner = acquire(&root, &binding(&root_id), &key).unwrap().unwrap();
        let ready = root.join("child-ready");
        let pending = ready.with_extension("pending");
        std::fs::write(&pending, b"lease-owned").unwrap();
        std::fs::rename(&pending, &ready).unwrap();
        // The parent kills this process while the actual production lease is
        // still owned. No Rust destructor or simulated PID check releases it.
        let mut byte = [0_u8];
        std::io::stdin().read_exact(&mut byte).unwrap();
        panic!("lease child must be terminated by its parent");
    }

    #[test]
    fn abrupt_supervisor_process_exit_releases_the_signed_lease_without_rust_cleanup() {
        let (_temp, root, key, root_id) = fixture();
        let test_module = module_path!().split_once("::").unwrap().1;
        let test_name = format!("{test_module}::lease_subprocess_owner");
        let mut child = ChildOwner(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture"])
                .env(CHILD_ROOT_ENV, &root)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let ready = root.join("child-ready");
        let deadline = Instant::now() + Duration::from_secs(15);
        while !ready.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "lease helper exited without acquiring ownership"
            );
            assert!(
                Instant::now() < deadline,
                "lease helper did not acquire ownership before its deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(std::fs::read(&ready).unwrap(), b"lease-owned");
        let binding = binding(&root_id);
        let original = std::fs::read(path(&root, NONCE)).unwrap();
        assert!(matches!(
            probe(&root, &binding, &key.verifying_key()).unwrap(),
            Probe::Live
        ));
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        assert!(matches!(
            probe(&root, &binding, &key.verifying_key()).unwrap(),
            Probe::Orphaned(_)
        ));
        assert_eq!(std::fs::read(path(&root, NONCE)).unwrap(), original);
    }

    #[test]
    fn staged_lease_publishes_same_locked_inode_and_drops_cleanly_when_unpublished() {
        let (_temp, root, key, root_id) = fixture();
        let binding = binding(&root_id);
        let lease_path = path(&root, NONCE);

        // Staging must not publish the final lease path; dropping removes its temp file.
        let unpublished = stage(&root, &binding, &key).unwrap();
        assert!(!lease_path.exists());
        assert!(matches!(
            probe(&root, &binding, &key.verifying_key()).unwrap(),
            Probe::Unproven
        ));
        drop(unpublished);
        assert!(!lease_path.exists());
        assert_eq!(
            std::fs::read_dir(root.join(DIRECTORY)).unwrap().count(),
            0,
            "dropping an unpublished staged lease must leave zero files behind"
        );

        // Publishing keeps the signed (dev, ino) and held flock continuous.
        let staged = stage(&root, &binding, &key).unwrap();
        let owner = staged.publish(&root).unwrap().unwrap();
        assert!(lease_path.exists());
        let original = std::fs::read(&lease_path).unwrap();
        assert!(matches!(
            probe(&root, &binding, &key.verifying_key()).unwrap(),
            Probe::Live
        ));
        // Second staged lease for the same nonce must refuse to clobber.
        let duplicate = stage(&root, &binding, &key).unwrap();
        assert!(duplicate.publish(&root).is_err());
        assert_eq!(std::fs::read(&lease_path).unwrap(), original);
        drop(owner);
        assert!(matches!(
            probe(&root, &binding, &key.verifying_key()).unwrap(),
            Probe::Orphaned(_)
        ));
    }
}
