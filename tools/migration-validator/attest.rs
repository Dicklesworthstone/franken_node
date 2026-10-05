#![forbid(unsafe_code)]

//! Attest the production validator's live measurements. There is deliberately
//! no sign-existing-report command. The private key must remain outside the
//! captured project; trusted guests still retain ambient OS authority.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[path = "../../crates/franken-node/src/migration/report_attestation.rs"]
pub mod report_attestation;
#[cfg(target_os = "linux")]
#[path = "../../crates/franken-node/src/migration/smoke_supervisor.rs"]
mod smoke_supervisor;
#[cfg(target_os = "linux")]
#[path = "../../crates/franken-node/src/migration/validation_suite.rs"]
pub mod validation_suite;

#[derive(Parser)]
#[command(version, about = "Sign freshly executed, passing Node/Bun/Franken project validation")]
struct Args {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Generate a new dedicated validator key and independently install its public anchor.
    Keygen {
        /// New absolute private-key path. Keep outside projects and version control.
        #[arg(long)]
        secret_key: PathBuf,
        /// New absolute public-key path, normally PROJECT/.franken-node/keys/migration-validation.pub.
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Capture and execute the current project, then attest a complete passing cohort.
    Run {
        project: PathBuf,
        #[arg(long)]
        native_bin: PathBuf,
        #[arg(long)]
        bun_bin: PathBuf,
        /// Dedicated 32-byte raw Ed25519 seed, mode 0600, outside the project.
        #[arg(long)]
        signing_key: PathBuf,
        /// New signed report path outside the project. Existing files are never replaced.
        #[arg(long)]
        out: PathBuf,
        /// Approve trusted project execution with your ambient authority, not an OS sandbox.
        #[arg(long, required = true)]
        execute: bool,
    },
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::{Context, Result, ensure};
    use ed25519_dalek::SigningKey;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    fn destination(path: &Path) -> Result<PathBuf> {
        ensure!(path.is_absolute(), "key and report destinations must be absolute");
        let parent = path.parent().context("destination parent missing")?.canonicalize()?;
        let name = path.file_name().context("destination filename missing")?;
        let path = parent.join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path),
            Err(error) => Err(error.into()),
            Ok(_) => anyhow::bail!("destination already exists; refusing to overwrite it"),
        }
    }

    fn create_key_file(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        File::open(path.parent().context("key parent missing")?)?.sync_all()?;
        Ok(())
    }

    fn keygen(secret: &Path, public: &Path) -> Result<()> {
        let secret = destination(secret)?;
        let public = destination(public)?;
        ensure!(secret != public, "secret and public destinations must differ");
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let seed = Zeroizing::new(key.to_bytes());
        // On a later I/O failure, retain the exclusively created key rather
        // than deleting it or silently replacing a concurrently installed key.
        create_key_file(&secret, seed.as_ref())?;
        create_key_file(&public, hex::encode(key.verifying_key().to_bytes()).as_bytes())?;
        println!("{}", serde_json::json!({
            "public_key": hex::encode(key.verifying_key().to_bytes()),
            "secret_key_written": true,
            "public_key_written": true
        }));
        Ok(())
    }

    fn load_secret(path: &Path, project: &Path) -> Result<SigningKey> {
        use rustix::fs::{Mode, OFlags, open};
        ensure!(path.is_absolute() && fs::symlink_metadata(path)?.is_file(),
            "signing key must be an absolute regular file, not a symlink");
        let path = path.canonicalize()?;
        ensure!(!path.starts_with(project), "signing key must remain outside the captured project");
        let mut file = File::from(open(&path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?);
        let metadata = file.metadata()?;
        ensure!(metadata.is_file() && metadata.len() == 32 && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1,
            "signing key must be an owner-only, single-link regular 32-byte raw seed");
        let mut seed = Zeroizing::new([0_u8; 32]);
        file.read_exact(seed.as_mut())?;
        let mut extra = [0_u8; 1];
        ensure!(file.read(&mut extra)? == 0, "signing key changed length");
        let after = file.metadata()?;
        ensure!(metadata.len() == after.len() && metadata.ctime() == after.ctime()
            && metadata.ctime_nsec() == after.ctime_nsec(), "signing key changed while reading");
        Ok(SigningKey::from_bytes(&seed))
    }

    fn execute(project: &Path, native: &Path, bun: &Path, key: &Path, out: &Path, approved: bool) -> Result<()> {
        use validation_suite::{native_replay, rewrite_candidate::RewriteCandidate};
        ensure!(approved, "--execute is required before running project code");
        let project = project.canonicalize().context("resolve project")?;
        let destination = destination(out)?;
        let destination = native_replay::output_destination(&destination, &[&project])?;
        let signing = load_secret(key, &project)?;
        let trusted = report_attestation::project_key(&project)?;
        ensure!(signing.verifying_key() == trusted,
            "signing key does not match the independently installed project validation key");

        let deadline = Instant::now() + Duration::from_secs(300);
        let mut captured = RewriteCandidate::capture(&project, deadline)?;
        captured.prepare(&[])?;
        let report = captured.validate_product(native, bun)?;
        captured.check_product_validation(&report)
            .with_context(|| format!("refusing to attest a nonpassing or incomplete live suite ({})", report.verdict))?;
        ensure!(report.native_runtime.sha256 != report.node_runtime.sha256
            && report.native_runtime.sha256 != report.bun_runtime.sha256,
            "attestation requires three distinct runtime executable hashes");
        captured.ensure_source_unchanged()?;
        ensure!(report_attestation::project_key(&project)? == trusted,
            "validation trust anchor changed during execution");
        let raw = serde_json::to_vec(&report)?;
        let sealed = report_attestation::seal(&raw, &signing)?;
        ensure!(report_attestation::verify(&sealed, &trusted)? == raw,
            "signed report failed local verification");
        captured.ensure_source_unchanged()?;
        let parent = destination.parent().context("report parent missing")?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(&sealed)?;
        temporary.as_file().sync_all()?;
        temporary.persist_noclobber(&destination).map_err(|error| error.error)?;
        File::open(parent)?.sync_all()?;
        println!("{}", serde_json::json!({
            "schema_version": report_attestation::SCHEMA,
            "report": destination,
            "signer_public_key": hex::encode(trusted.to_bytes()),
            "total_tests": report.total_tests,
            "verdict": report.verdict,
            "release_certification": false
        }));
        Ok(())
    }

    pub(super) fn run(args: Args) -> Result<()> {
        match args.command {
            Action::Keygen { secret_key, public_key } => keygen(&secret_key, &public_key),
            Action::Run { project, native_bin, bun_bin, signing_key, out, execute: approved } =>
                execute(&project, &native_bin, &bun_bin, &signing_key, &out, approved),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{PermissionsExt, symlink};

        #[test]
        fn keygen_is_exclusive_and_produces_a_matching_owner_only_pair() {
            let root = tempfile::tempdir().unwrap();
            let project = root.path().join("project");
            fs::create_dir(&project).unwrap();
            let secret = root.path().join("validator.seed");
            let public = root.path().join("validator.pub");
            keygen(&secret, &public).unwrap();
            assert_eq!(fs::metadata(&secret).unwrap().mode() & 0o777, 0o600);
            let before = fs::read(&secret).unwrap();
            assert!(keygen(&secret, &public).is_err());
            assert_eq!(fs::read(&secret).unwrap(), before);
            let loaded = load_secret(&secret, &project).unwrap();
            assert_eq!(hex::encode(loaded.verifying_key().to_bytes()), fs::read_to_string(public).unwrap());
        }

        #[test]
        fn key_paths_cannot_expose_the_seed_through_a_capture_or_link() {
            let root = tempfile::tempdir().unwrap();
            let project = root.path().join("project");
            fs::create_dir(&project).unwrap();
            let secret = root.path().join("validator.seed");
            create_key_file(&secret, &[7; 32]).unwrap();
            assert!(load_secret(&secret, root.path()).is_err());
            let link = root.path().join("linked");
            symlink(&secret, &link).unwrap();
            assert!(load_secret(&link, &project).is_err());
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_secret(&secret, &project).is_err());
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
            fs::hard_link(&secret, project.join("leaked-key")).unwrap();
            assert!(load_secret(&secret, &project).is_err());
        }

        #[test]
        fn missing_consent_or_mismatched_key_fails_before_guest_execution() {
            let root = tempfile::tempdir().unwrap();
            let project = root.path().join("project");
            fs::create_dir_all(project.join(".franken-node/keys")).unwrap();
            let secret = root.path().join("validator.seed");
            create_key_file(&secret, &[7; 32]).unwrap();
            fs::write(project.join(report_attestation::PUBLIC_KEY_PATH),
                hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes())).unwrap();
            let out = root.path().join("report.json");
            assert!(execute(&project, Path::new("/missing-native"), Path::new("/missing-bun"), &secret, &out, false)
                .unwrap_err().to_string().contains("--execute"));
            assert!(execute(&project, Path::new("/missing-native"), Path::new("/missing-bun"), &secret, &out, true)
                .unwrap_err().to_string().contains("does not match"));
            assert!(!out.exists());
        }

        #[test]
        fn failed_live_measurement_never_publishes_an_attestation() {
            // Actual production capture/execution with deliberately failing
            // executables, NOT substitutes claimed to pass Bun/Franken parity.
            let root = tempfile::tempdir().unwrap();
            let project = root.path().join("project");
            fs::create_dir_all(project.join(".franken-node/keys")).unwrap();
            fs::write(project.join("case.test.js"), "console.log(42);\n").unwrap();
            let secret = root.path().join("validator.seed");
            create_key_file(&secret, &[7; 32]).unwrap();
            fs::write(project.join(report_attestation::PUBLIC_KEY_PATH),
                hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes())).unwrap();
            let out = root.path().join("report.json");
            let result = execute(&project, Path::new("/bin/false"), Path::new("/bin/true"), &secret, &out, true);
            assert!(result.unwrap_err().to_string().contains("nonpassing or incomplete live suite"));
            assert!(!out.exists());
            assert_eq!(fs::read(project.join("case.test.js")).unwrap(), b"console.log(42);\n");
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    match linux::run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("migration attestation refused: {error:#}");
            ExitCode::from(1)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        eprintln!("migration attestation execution is supported on Linux only");
        ExitCode::from(2)
    }
}
