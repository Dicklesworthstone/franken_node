#![forbid(unsafe_code)]

//! Attest the production validator's live measurements. There is deliberately
//! no sign-existing-report command. Original/candidate comparison uses the
//! existing one-use input approval and three-runtime execution APIs. Private
//! keys stay outside BOTH projects; trusted guests retain ambient authority.

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
#[command(version, about = "Attest freshly executed Node/Bun/Franken project validation")]
struct Args {
    #[command(subcommand)]
    command: Action,
}

#[derive(clap::Args)]
struct Selection {
    /// Original project executed by Node and Bun.
    project: PathBuf,
    /// Rewritten candidate executed by native Franken. Requires both reviewed input hashes.
    #[arg(long, requires_all = ["expected_input_sha256", "expected_candidate_input_sha256"])]
    migrated_project: Option<PathBuf>,
    /// Independently reviewed original hash from the ordinary suite operator's --list-tests.
    #[arg(long, requires = "expected_candidate_input_sha256")]
    expected_input_sha256: Option<String>,
    /// Independently reviewed candidate hash. For one tree repeat the original hash.
    #[arg(long, requires = "expected_input_sha256")]
    expected_candidate_input_sha256: Option<String>,
    /// Also retain a signed complete native FAIL with successful agreeing references.
    /// Validation still exits nonzero. Never signs ERROR or INCONCLUSIVE evidence.
    #[arg(long)]
    attest_regression: bool,
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
    /// Execute original Node/Bun and candidate Franken, then attest the permitted measured result.
    Run {
        #[command(flatten)]
        inputs: Selection,
        #[arg(long)]
        native_bin: PathBuf,
        #[arg(long)]
        bun_bin: PathBuf,
        /// Dedicated 32-byte raw Ed25519 seed, mode 0600, outside both input projects.
        #[arg(long)]
        signing_key: PathBuf,
        /// New signed report path outside both input projects. Never replaces an existing file.
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
    use validation_suite::{ApprovedInputs, native_replay, rewrite_candidate::RewriteCandidate};
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

    fn load_secret(path: &Path, projects: &[&Path]) -> Result<SigningKey> {
        use rustix::fs::{Mode, OFlags, open};
        ensure!(path.is_absolute() && fs::symlink_metadata(path)?.is_file(),
            "signing key must be an absolute regular file, not a symlink");
        let path = path.canonicalize()?;
        ensure!(!projects.iter().any(|project| path.starts_with(project)),
            "signing key must remain outside both captured projects");
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

    /// Resolve aliases once, and reject incomplete approvals even when a caller
    /// bypasses Clap. No keys are opened and no executable is resolved here.
    fn resolve_inputs(inputs: &Selection) -> Result<(PathBuf, PathBuf)> {
        let pins = (&inputs.expected_input_sha256, &inputs.expected_candidate_input_sha256);
        ensure!(pins.0.is_some() == pins.1.is_some(), "both reviewed input hashes are required");
        ensure!(inputs.migrated_project.is_none() || pins.0.is_some(),
            "--migrated-project requires both reviewed input hashes");
        for pin in [pins.0, pins.1].into_iter().flatten() {
            ensure!(pin.len() == 64 && pin.bytes().all(|b|
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "reviewed input hashes must be 64 lowercase hexadecimal characters");
        }
        let original = inputs.project.canonicalize().context("resolve original project")?;
        let candidate = inputs.migrated_project.as_deref().unwrap_or(&inputs.project)
            .canonicalize().context("resolve candidate project")?;
        ensure!(original.is_dir() && candidate.is_dir(), "input projects must be directories");
        ensure!(original == candidate || (!original.starts_with(&candidate) && !candidate.starts_with(&original)),
            "distinct input projects must not be nested");
        Ok((original, candidate))
    }

    /// Recapture only to reject stale evidence, never to redefine the inputs
    /// that were executed. Both role digests must match the pre-execution pins.
    /// Returning the current candidate inventory lets the normal product
    /// admission routine check every measured observation against that capture.
    fn current_inventory(
        original: &Path,
        candidate: &Path,
        original_pin: &str,
        candidate_pin: &str,
        deadline: Instant,
    ) -> Result<Vec<PathBuf>> {
        let original_now = RewriteCandidate::capture(original, deadline)?;
        ensure!(original_now.input_sha256() == original_pin,
            "original project changed during attested validation");
        let candidate_now = if candidate == original {
            None
        } else {
            Some(RewriteCandidate::capture(candidate, deadline)?)
        };
        let current = candidate_now.as_ref().unwrap_or(&original_now);
        ensure!(current.input_sha256() == candidate_pin,
            "candidate project changed during attested validation");
        let tests = current.test_inventory()?;
        original_now.ensure_source_unchanged()?;
        if let Some(candidate_now) = candidate_now {
            candidate_now.ensure_source_unchanged()?;
        }
        Ok(tests)
    }

    fn execute(inputs: &Selection, native: &Path, bun: &Path, key: &Path, out: &Path, approved: bool) -> Result<()> {
        ensure!(approved, "--execute is required before running project code");
        let (original, candidate) = resolve_inputs(inputs)?;
        let destination = destination(out)?;
        let destination = native_replay::output_destination(&destination, &[&original, &candidate])?;
        let signing = load_secret(key, &[&original, &candidate])?;
        // The candidate is the project that will consume this approval. Never
        // learn authority from the original tree or from a signed envelope.
        let trusted = report_attestation::project_key(&candidate)?;
        ensure!(signing.verifying_key() == trusted,
            "signing key does not match the independently installed candidate validation key");

        let deadline = Instant::now() + Duration::from_secs(300);
        let (original_pin, candidate_pin) = match (
            &inputs.expected_input_sha256, &inputs.expected_candidate_input_sha256,
        ) {
            (Some(original), Some(candidate)) => (original.clone(), candidate.clone()),
            (None, None) => {
                // Same-tree mode retains --execute approval of the current
                // capture. Cross-tree mode ALWAYS requires reviewed pins.
                let captured = RewriteCandidate::capture(&original, deadline)?;
                let pin = captured.input_sha256().to_owned();
                (pin.clone(), pin)
            }
            _ => anyhow::bail!("both reviewed input hashes are required"),
        };
        // The production API captures and compares BOTH pins before runtime
        // discovery, checks identical inventories/expectations, and consumes
        // the exact immutable original/candidate snapshots once. There is no
        // second execution path or same-tree fallback for migrated projects.
        let admitted = ApprovedInputs::capture(
            &original, Some(&candidate), &original_pin, &candidate_pin,
        )?;
        let report = admitted.run_product(native, bun, true)?;
        let tests = current_inventory(&original, &candidate, &original_pin, &candidate_pin, deadline)?;
        let regression = inputs.attest_regression && report.verdict == "FAIL";
        if regression {
            // Reuse the replay verifier's complete observation reconstruction.
            // This is signed negative evidence, never an approval or a PASS
            // projection of a failed/incomplete measurement.
            native_replay::failure_capture::product::check_native_regression(
                &report, &original_pin, &candidate_pin, &tests,
            ).context("refusing to attest incomplete or inconsistent native regression evidence")?;
        } else {
            report.check_admission(&original_pin, &candidate_pin, &tests)
                .with_context(|| format!("refusing to attest a nonpassing or incomplete live suite ({})", report.verdict))?;
        }
        ensure!(report.native_runtime.sha256 != report.node_runtime.sha256
            && report.native_runtime.sha256 != report.bun_runtime.sha256,
            "attestation requires three distinct runtime executable hashes");
        ensure!(report_attestation::project_key(&candidate)? == trusted,
            "validation trust anchor changed during execution");
        let raw = serde_json::to_vec(&report)?;
        let sealed = report_attestation::seal(&raw, &signing)?;
        ensure!(report_attestation::verify(&sealed, &trusted)? == raw,
            "signed report failed local verification");
        current_inventory(&original, &candidate, &original_pin, &candidate_pin, deadline)?;
        ensure!(report_attestation::project_key(&candidate)? == trusted,
            "validation trust anchor changed before publication");
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
            "input_sha256": report.input_sha256,
            "candidate_input_sha256": report.candidate_input_sha256,
            "total_tests": report.total_tests,
            "verdict": report.verdict,
            "regression_attested": regression,
            "release_certification": false
        }));
        // The artifact's successful publication must not make a failed suite
        // succeed in a shell/CI pipeline. The signed FAIL remains available for
        // an explicitly invoked rollout decision or offline investigation.
        ensure!(!regression,
            "native regression attested; validation remains FAIL; signed evidence was published");
        Ok(())
    }

    pub(super) fn run(args: Args) -> Result<()> {
        match args.command {
            Action::Keygen { secret_key, public_key } => keygen(&secret_key, &public_key),
            Action::Run { inputs, native_bin, bun_bin, signing_key, out, execute: approved } =>
                execute(&inputs, &native_bin, &bun_bin, &signing_key, &out, approved),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{PermissionsExt, symlink};

        fn current(project: &Path) -> Selection {
            Selection {
                project: project.into(), migrated_project: None,
                expected_input_sha256: None, expected_candidate_input_sha256: None,
                attest_regression: false,
            }
        }

        fn pin(project: &Path) -> String {
            RewriteCandidate::capture(project, Instant::now() + Duration::from_secs(30))
                .unwrap().input_sha256().to_owned()
        }

        fn pair(root: &Path) -> (Selection, PathBuf, PathBuf) {
            let original = root.join("original");
            let candidate = root.join("candidate");
            fs::create_dir_all(&original).unwrap();
            fs::create_dir_all(candidate.join(".franken-node/keys")).unwrap();
            for (project, text) in [(&original, "console.log(21 + 21);\n"), (&candidate, "console.log(42);\n")] {
                fs::write(project.join("case.test.js"), text).unwrap();
            }
            let secret = root.join("validator.seed");
            create_key_file(&secret, &[7; 32]).unwrap();
            fs::write(candidate.join(report_attestation::PUBLIC_KEY_PATH),
                hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes())).unwrap();
            let selection = Selection {
                expected_input_sha256: Some(pin(&original)),
                expected_candidate_input_sha256: Some(pin(&candidate)),
                project: original, migrated_project: Some(candidate),
                attest_regression: false,
            };
            (selection, secret, root.join("signed.json"))
        }

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
            let loaded = load_secret(&secret, &[&project]).unwrap();
            assert_eq!(hex::encode(loaded.verifying_key().to_bytes()), fs::read_to_string(public).unwrap());
        }

        #[test]
        fn key_paths_cannot_expose_the_seed_through_a_capture_or_link() {
            let root = tempfile::tempdir().unwrap();
            let project = root.path().join("project");
            fs::create_dir(&project).unwrap();
            let secret = root.path().join("validator.seed");
            create_key_file(&secret, &[7; 32]).unwrap();
            assert!(load_secret(&secret, &[root.path()]).is_err());
            let link = root.path().join("linked");
            symlink(&secret, &link).unwrap();
            assert!(load_secret(&link, &[&project]).is_err());
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_secret(&secret, &[&project]).is_err());
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
            fs::hard_link(&secret, project.join("leaked-key")).unwrap();
            assert!(load_secret(&secret, &[&project]).is_err());
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
            assert!(execute(&current(&project), Path::new("/missing-native"), Path::new("/missing-bun"), &secret, &out, false)
                .unwrap_err().to_string().contains("--execute"));
            assert!(execute(&current(&project), Path::new("/missing-native"), Path::new("/missing-bun"), &secret, &out, true)
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
            let result = execute(&current(&project), Path::new("/bin/false"), Path::new("/bin/true"), &secret, &out, true);
            assert!(result.unwrap_err().to_string().contains("nonpassing or incomplete live suite"));
            assert!(!out.exists());
            assert_eq!(fs::read(project.join("case.test.js")).unwrap(), b"console.log(42);\n");
        }

        #[test]
        fn migrated_cli_requires_complete_role_pins_and_execution_consent() {
            let base = ["attest", "run", "/original", "--migrated-project", "/candidate",
                "--native-bin", "/native", "--bun-bin", "/bun", "--signing-key", "/key", "--out", "/out"];
            let original = "a".repeat(64);
            let candidate = "b".repeat(64);
            let mut args = base.to_vec();
            assert!(Args::try_parse_from(&args).is_err());
            args.push("--execute");
            assert!(Args::try_parse_from(&args).is_err());
            args.extend(["--expected-input-sha256", &original]);
            assert!(Args::try_parse_from(&args).is_err());
            args.extend(["--expected-candidate-input-sha256", &candidate]);
            assert!(Args::try_parse_from(&args).is_ok());
        }

        #[test]
        fn library_call_cannot_bypass_missing_or_malformed_role_pins() {
            let mut inputs = current(Path::new("/nonexistent-original"));
            inputs.migrated_project = Some("/nonexistent-candidate".into());
            assert!(resolve_inputs(&inputs).unwrap_err().to_string().contains("both reviewed"));
            inputs.expected_input_sha256 = Some("a".repeat(64));
            assert!(resolve_inputs(&inputs).unwrap_err().to_string().contains("both reviewed"));
            inputs.expected_candidate_input_sha256 = Some("B".repeat(64));
            assert!(resolve_inputs(&inputs).unwrap_err().to_string().contains("lowercase"));
        }

        #[test]
        fn wrong_or_swapped_role_hashes_fail_before_runtime_discovery() {
            let root = tempfile::tempdir().unwrap();
            let (mut inputs, secret, out) = pair(root.path());
            let original = inputs.expected_input_sha256.clone();
            let candidate = inputs.expected_candidate_input_sha256.clone();
            for (left, right, role) in [
                (Some("0".repeat(64)), candidate.clone(), "original"),
                (original.clone(), Some("0".repeat(64)), "candidate"),
                (candidate.clone(), original.clone(), "original"),
            ] {
                inputs.expected_input_sha256 = left;
                inputs.expected_candidate_input_sha256 = right;
                let error = execute(&inputs, Path::new("/missing-native"), Path::new("/missing-bun"), &secret, &out, true).unwrap_err();
                assert!(format!("{error:#}").contains(&format!("{role} captured input does not match")), "{error:#}");
                assert!(!out.exists());
            }
        }

        #[test]
        fn candidate_anchor_controls_signing_not_the_original_anchor() {
            let root = tempfile::tempdir().unwrap();
            let (inputs, secret, out) = pair(root.path());
            let candidate = inputs.migrated_project.as_ref().unwrap();
            fs::create_dir_all(inputs.project.join(".franken-node/keys")).unwrap();
            fs::write(inputs.project.join(report_attestation::PUBLIC_KEY_PATH),
                hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes())).unwrap();
            fs::write(candidate.join(report_attestation::PUBLIC_KEY_PATH),
                hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes())).unwrap();
            let error = execute(&inputs, Path::new("/missing-native"), Path::new("/missing-bun"), &secret, &out, true).unwrap_err();
            assert!(error.to_string().contains("candidate validation key"), "{error:#}");
            assert!(!out.exists());
        }

        #[test]
        fn private_seed_and_report_must_stay_outside_both_trees() {
            let root = tempfile::tempdir().unwrap();
            let (inputs, secret, out) = pair(root.path());
            for project in [&inputs.project, inputs.migrated_project.as_ref().unwrap()] {
                let leaked = project.join("validator.seed");
                create_key_file(&leaked, &[7; 32]).unwrap();
                let error = execute(&inputs, Path::new("/missing-native"), Path::new("/missing-bun"), &leaked, &out, true).unwrap_err();
                assert!(error.to_string().contains("outside both"), "{error:#}");
                assert!(execute(&inputs, Path::new("/missing-native"), Path::new("/missing-bun"), &secret, &project.join("signed.json"), true).is_err());
                assert!(!project.join("signed.json").exists());
            }
            assert!(!out.exists());
        }

        #[test]
        fn nested_projects_are_rejected_after_resolving_aliases() {
            let root = tempfile::tempdir().unwrap();
            let (mut inputs, _, _) = pair(root.path());
            let nested = inputs.project.join("nested");
            fs::create_dir(&nested).unwrap();
            let alias = root.path().join("alias");
            symlink(&nested, &alias).unwrap();
            inputs.migrated_project = Some(alias);
            assert!(resolve_inputs(&inputs).unwrap_err().to_string().contains("nested"));
        }

        #[test]
        fn post_execution_recapture_never_redefines_either_approved_tree() {
            for mutate_original in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let (inputs, _, _) = pair(root.path());
                let candidate = inputs.migrated_project.as_ref().unwrap();
                let original_pin = inputs.expected_input_sha256.as_ref().unwrap();
                let candidate_pin = inputs.expected_candidate_input_sha256.as_ref().unwrap();
                let deadline = Instant::now() + Duration::from_secs(30);
                let tests = current_inventory(&inputs.project, candidate, original_pin, candidate_pin, deadline).unwrap();
                assert_eq!(tests, vec![PathBuf::from("case.test.js")]);
                let changed = if mutate_original { &inputs.project } else { candidate };
                fs::write(changed.join("dependency.json"), b"changed").unwrap();
                let error = current_inventory(&inputs.project, candidate, original_pin, candidate_pin, deadline).unwrap_err();
                assert!(error.to_string().contains(if mutate_original { "original project changed" } else { "candidate project changed" }));
            }
        }

        #[test]
        fn changed_golden_or_test_selection_is_refused_before_execution() {
            let root = tempfile::tempdir().unwrap();
            let (mut inputs, secret, out) = pair(root.path());
            let candidate = inputs.migrated_project.as_ref().unwrap();
            for project in [&inputs.project, candidate] {
                fs::create_dir_all(project.join(".franken-node")).unwrap();
                fs::write(project.join(".franken-node/migration-tests.json"),
                    br#"{"schema_version":"franken-node/migration-tests/v1","tests":["case.test.js"],"expectations":{"case.test.js":{"stdout":"expected.txt"}}}"#).unwrap();
                fs::write(project.join("expected.txt"), if project == candidate { "different\n" } else { "42\n" }).unwrap();
            }
            inputs.expected_input_sha256 = Some(pin(&inputs.project));
            inputs.expected_candidate_input_sha256 = Some(pin(candidate));
            let error = execute(&inputs, Path::new("/missing-native"), Path::new("/missing-bun"), &secret, &out, true).unwrap_err();
            assert!(format!("{error:#}").contains("captured stdout expectation bytes differ"), "{error:#}");
            assert!(!out.exists());
        }

        #[test]
        fn failing_live_original_candidate_comparison_keeps_both_sources_and_publishes_nothing() {
            let root = tempfile::tempdir().unwrap();
            let (inputs, secret, out) = pair(root.path());
            let error = execute(&inputs, Path::new("/bin/false"), Path::new("/bin/true"), &secret, &out, true).unwrap_err();
            assert!(error.to_string().contains("nonpassing or incomplete live suite"), "{error:#}");
            assert!(!out.exists());
            assert_eq!(pin(&inputs.project), inputs.expected_input_sha256.unwrap());
            assert_eq!(pin(inputs.migrated_project.as_ref().unwrap()), inputs.expected_candidate_input_sha256.unwrap());
        }

        #[test]
        fn native_regression_requires_opt_in_and_keeps_a_signed_fail_nonzero() {
            // Real production execution with Node plus intentionally selected
            // true/false test executables. This proves the evidence pipeline,
            // not Bun/Franken compatibility or runtime-brand authenticity.
            let root = tempfile::tempdir().unwrap();
            let (mut inputs, secret, out) = pair(root.path());
            let candidate = inputs.migrated_project.as_ref().unwrap().clone();
            for project in [&inputs.project, &candidate] {
                fs::write(project.join("case.test.js"), "globalThis.answer = 42;\n").unwrap();
            }
            inputs.expected_input_sha256 = Some(pin(&inputs.project));
            inputs.expected_candidate_input_sha256 = Some(pin(&candidate));
            let invoke = |inputs: &Selection| execute(inputs, Path::new("/bin/false"),
                Path::new("/bin/true"), &secret, &out, true);
            assert!(invoke(&inputs).is_err());
            assert!(!out.exists());
            inputs.attest_regression = true;
            let error = invoke(&inputs).unwrap_err();
            assert!(error.to_string().contains("native regression attested"), "{error:#}");
            let envelope = fs::read(&out).unwrap();
            let body = report_attestation::verify(&envelope,
                &report_attestation::project_key(&candidate).unwrap()).unwrap();
            let report: validation_suite::product_oracle::ProductReport =
                serde_json::from_slice(&body).unwrap();
            assert_eq!(report.verdict, "FAIL");
            assert_eq!(report.native_divergences, 1);
            assert_eq!(report.reference_failures, 0);
            assert_eq!(report.reference_divergences, 0);
            assert!(report.check_admission(inputs.expected_input_sha256.as_ref().unwrap(),
                inputs.expected_candidate_input_sha256.as_ref().unwrap(),
                &[PathBuf::from("case.test.js")]).is_err());
            assert_eq!(pin(&inputs.project), inputs.expected_input_sha256.as_ref().unwrap().as_str());
            assert_eq!(pin(&candidate), inputs.expected_candidate_input_sha256.as_ref().unwrap().as_str());
            assert!(invoke(&inputs).unwrap_err().to_string().contains("already exists"));
            assert_eq!(fs::read(out).unwrap(), envelope);
        }

        #[test]
        fn regression_opt_in_never_signs_reference_disagreement_or_incomplete_runs() {
            for source in [
                "console.log('reference disagreement');\n",
                "process.stdout.write('x'.repeat(17 * 1024 * 1024));\n",
            ] {
                let root = tempfile::tempdir().unwrap();
                let (mut inputs, secret, out) = pair(root.path());
                let candidate = inputs.migrated_project.as_ref().unwrap();
                for project in [&inputs.project, candidate] {
                    fs::write(project.join("case.test.js"), source).unwrap();
                }
                inputs.expected_input_sha256 = Some(pin(&inputs.project));
                inputs.expected_candidate_input_sha256 = Some(pin(candidate));
                inputs.attest_regression = true;
                let error = execute(&inputs, Path::new("/bin/false"), Path::new("/bin/true"),
                    &secret, &out, true).unwrap_err();
                assert!(error.to_string().contains("nonpassing or incomplete"), "{error:#}");
                assert!(!out.exists());
            }
        }

        #[test]
        fn regression_flag_does_not_replace_execution_consent() {
            let base = ["attest", "run", "/project", "--native-bin", "/native",
                "--bun-bin", "/bun", "--signing-key", "/key", "--out", "/out",
                "--attest-regression"];
            assert!(Args::try_parse_from(base).is_err());
            let mut approved = base.to_vec();
            approved.push("--execute");
            let args = Args::try_parse_from(approved).unwrap();
            assert!(matches!(args.command, Action::Run {
                inputs: Selection { attest_regression: true, .. }, execute: true, ..
            }));
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    match linux::run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("migration validation: {error:#}");
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
