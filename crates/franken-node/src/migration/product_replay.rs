//! Complete three-runtime failure archives and exact-input replay.
//!
//! The archive reuses the pair capsule's bounded path/blob/link codec, but has
//! its own schema and hash domain. Bun observations are never projected away.
//! Imported command paths are evidence only; execution uses local selections.

use super::super::{Blob, CapsuleSummary, CapturedInputs, ExportedInputs, HashWriter, Invocation,
    LEG_TIMEOUT, MAX_CAPSULE_BYTES, MAX_ENTRIES, MAX_EXPANDED_BYTES, Snapshot, StoredSnapshot,
    TOTAL_TIMEOUT, budget, implementation_hash, is_hash, matched_tests, open_regular,
    output_destination, restore_snapshot, runtime_invocations, same_file_version, same_runtime,
    store_snapshot, workspace_effects};
use super::super::super::product_oracle::{self, CaseOutcome, ProductReport};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[path = "product_minimizer.rs"]
pub mod minimizer;

const SCHEMA: &str = "franken-node/product-migration-capsule/v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    schema_version: String,
    implementation_sha256: String,
    original: StoredSnapshot,
    candidate: Option<StoredSnapshot>,
    blobs: Vec<Blob>,
    expected: ProductReport,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capsule { payload: Payload, content_sha256: String }

/// Contains source bytes. Deliberately not Debug or Serialize.
pub struct CapturedProduct {
    pub report: ProductReport,
    capsule: Capsule,
    projects: [PathBuf; 2],
    unavailable: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReplayResult {
    pub schema_version: String,
    pub verdict: String,
    pub content_sha256: String,
    pub captured_verdict: String,
    pub mismatched_tests: Vec<String>,
    pub execution_performed: bool,
    pub environment_reproduced: bool,
    pub release_certification: bool,
    pub validation: ProductReport,
}

fn implementation() -> String {
    let mut hash = Sha256::new();
    hash.update(b"franken-node/product-replay-implementation/v1\0");
    for source in [implementation_hash(), include_str!("product_replay.rs").to_owned(),
        include_str!("product_oracle.rs").to_owned()] {
        hash.update((source.len() as u64).to_le_bytes());
        hash.update(source.as_bytes());
    }
    hex::encode(hash.finalize())
}

fn payload_hash(payload: &Payload) -> Result<String> {
    let mut writer = HashWriter(Sha256::new());
    writer.0.update(b"franken-node/product-migration-capsule/v1\0");
    serde_json::to_writer(&mut writer, payload)?;
    Ok(hex::encode(writer.0.finalize()))
}

fn summary(capsule: &Capsule) -> CapsuleSummary {
    let expected = &capsule.payload.expected;
    CapsuleSummary {
        schema_version: SCHEMA.into(), content_sha256: capsule.content_sha256.clone(),
        input_sha256: expected.input_sha256.clone(), candidate_input_sha256: expected.candidate_input_sha256.clone(),
        captured_verdict: expected.verdict.clone(), total_tests: expected.total_tests,
        tests: expected.cases.iter().map(|row| row.test.clone()).collect(), execution_performed: false,
        environment_reproduced: false, release_certification: false,
    }
}

// Validate complete FAIL/INCONCLUSIVE evidence too, not only admission PASS.
// Reconstruct every classification from observations instead of trusting the
// summary, including reference disagreement and native differences together.
fn complete(report: &ProductReport, original: &Snapshot, candidate: &Snapshot) -> Result<()> {
    let tests = matched_tests(original, candidate)?;
    ensure!(report.schema_version == "franken-node/product-validation-suite/v1"
        && report.oracle == "L1-node-bun-franken-node" && !report.release_certification
        && report.input_sha256 == original.digest && report.candidate_input_sha256 == candidate.digest,
        "product capsule input identity or schema mismatch");
    let exclusions: Vec<String> = if report.filesystem_comparison {
        workspace_effects::EXCLUSIONS.iter().map(|s| (*s).into()).collect()
    } else { Vec::new() };
    ensure!(report.filesystem_exclusions == exclusions && report.scope == if report.filesystem_comparison {
        "captured-test-process-and-workspace-delta"
    } else { "captured-test-process-stdout-stderr-exit" }, "product capsule comparison scope mismatch");
    ensure!(report.total_tests == tests.len() && report.cases.len() == tests.len()
        && report.errored == 0 && report.skipped == 0 && report.errors.is_empty(),
        "incomplete product capsule execution evidence");
    ensure!(report.distinct_reference_binaries && report.node_runtime.sha256 != report.bun_runtime.sha256,
        "product capsule requires distinct reference executable hashes");
    for runtime in [&report.node_runtime, &report.bun_runtime, &report.native_runtime] {
        ensure!(runtime.executable.is_absolute() && is_hash(&runtime.sha256), "invalid product runtime identity");
    }
    let (mut passed, mut reference_failures, mut reference_divergences, mut native_divergences) = (0, 0, 0, 0);
    for (test, row) in tests.iter().zip(&report.cases) {
        ensure!(test.to_str() == Some(row.test.as_str()) && row.errors.is_empty(),
            "product capsule test inventory or execution mismatch");
        let node = row.node.as_ref().context("missing Node observation")?;
        let bun = row.bun.as_ref().context("missing Bun observation")?;
        let native = row.native.as_ref().context("missing native observation")?;
        let mut divergences = Vec::new();
        for (role, run) in [("node", node), ("bun", bun), ("native", native)] {
            ensure!(run.exit_code.is_some() != run.signal.is_some()
                && run.exit_code.is_none_or(|code| (0..=255).contains(&code))
                && run.signal.is_none_or(|signal| (1..=127).contains(&signal)),
                "invalid product process termination evidence");
            ensure!(is_hash(&run.stdout.sha256) && is_hash(&run.stderr.sha256)
                && run.stdout.bytes <= 16 * 1024 * 1024 && run.stderr.bytes <= 16 * 1024 * 1024,
                "invalid product process stream evidence");
            ensure!(run.workspace_delta.is_some() == report.filesystem_comparison,
                "missing or unexpected product workspace evidence");
            if let Some(delta) = &run.workspace_delta {
                ensure!(is_hash(&delta.sha256) && delta.changes.len() == delta.changed_paths.min(20)
                    && delta.details_truncated == (delta.changed_paths > 20), "invalid product workspace summary");
            }
            if run.exit_code != Some(0) { divergences.push(format!("{role}:unsuccessful_exit")); }
        }
        let mut reference_mismatch = false;
        let mut native_mismatch = false;
        for (pair, right, mismatch) in [("node/bun", bun, &mut reference_mismatch),
            ("node/native", native, &mut native_mismatch)] {
            for (different, channel) in [(node.stdout != right.stdout, "stdout:byte_mismatch"),
                (node.stderr != right.stderr, "stderr:byte_mismatch"),
                (node.workspace_delta != right.workspace_delta, "filesystem:workspace_delta_mismatch")] {
                if different { *mismatch = true; divergences.push(format!("{pair}:{channel}")); }
            }
        }
        let outcome = if node.exit_code != Some(0) || bun.exit_code != Some(0) {
            reference_failures += 1; CaseOutcome::ReferenceFailure
        } else if reference_mismatch { reference_divergences += 1; CaseOutcome::ReferenceDivergence }
        else if native.exit_code != Some(0) || native_mismatch { native_divergences += 1; CaseOutcome::NativeDivergence }
        else { passed += 1; CaseOutcome::Match };
        ensure!(row.outcome == outcome && row.divergences == divergences,
            "product capsule verdict disagrees with measured observations");
    }
    let verdict = if reference_failures + reference_divergences > 0 { "INCONCLUSIVE" }
        else if native_divergences > 0 { "FAIL" } else { "PASS" };
    ensure!(report.passed == passed && report.failed == tests.len() - passed
        && report.reference_failures == reference_failures && report.reference_divergences == reference_divergences
        && report.native_divergences == native_divergences && report.verdict == verdict,
        "product capsule summary disagrees with measured cases");
    Ok(())
}

fn stored(original: &Snapshot, candidate: &Snapshot, deadline: Instant)
    -> Result<(StoredSnapshot, Option<StoredSnapshot>, Vec<Blob>)> {
    let mut blobs = BTreeMap::new();
    let mut expanded = 0;
    let mut metadata = 0;
    let stored_original = store_snapshot(original, &mut blobs, &mut expanded, &mut metadata, deadline)?;
    let stored_candidate = if original.digest == candidate.digest { None } else {
        Some(store_snapshot(candidate, &mut blobs, &mut expanded, &mut metadata, deadline)?)
    };
    Ok((stored_original, stored_candidate, blobs.into_iter().map(|(sha256, hex)| Blob { sha256, hex }).collect()))
}

impl CapturedProduct {
    pub fn write_capsule(&self, path: &Path) -> Result<CapsuleSummary> {
        ensure!(self.unavailable.is_none(), "product run is not replayable: {}",
            self.unavailable.as_deref().unwrap_or_default());
        let path = output_destination(path, &[&self.projects[0], &self.projects[1]])?;
        let encoded = serde_json::to_vec(&self.capsule)?;
        ensure!(encoded.len() <= MAX_CAPSULE_BYTES, "serialized product capsule exceeds 128 MiB");
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        let mut result = summary(&self.capsule);
        result.execution_performed = true;
        Ok(result)
    }
}

fn captured(report: ProductReport, snapshots: [&Snapshot; 2], projects: [PathBuf; 2],
    encoded: (StoredSnapshot, Option<StoredSnapshot>, Vec<Blob>)) -> Result<CapturedProduct> {
    let unavailable = complete(&report, snapshots[0], snapshots[1]).err().map(|error| format!("{error:#}"));
    let (original, candidate, blobs) = encoded;
    let payload = Payload { schema_version: SCHEMA.into(), implementation_sha256: implementation(),
        original, candidate, blobs, expected: report.clone() };
    let content_sha256 = payload_hash(&payload)?;
    Ok(CapturedProduct { report, capsule: Capsule { payload, content_sha256 }, projects, unavailable })
}

/// Capture both trees and check archive limits before executing any project.
pub fn capture_project(project: &Path, migrated: Option<&Path>, native: &Path, bun: &Path,
    filesystem: bool) -> Result<CapturedProduct> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let inputs = CapturedInputs::capture(project, migrated, deadline)?;
    let snapshots = [&inputs.reference, inputs.candidate_snapshot()];
    let encoded = stored(snapshots[0], snapshots[1], deadline)?;
    let report = product_oracle::run_captured([&inputs.reference_root, &inputs.candidate_root],
        snapshots, native, bun, deadline, filesystem)?;
    captured(report, snapshots, [inputs.reference_root.clone(), inputs.candidate_root.clone()], encoded)
}

// Used only by the live checked-rewrite retention capability, never to import
// external evidence. Inputs are its immutable original and prepared candidate.
pub(super) fn from_measured(report: &ProductReport, snapshots: [&Snapshot; 2], projects: [PathBuf; 2],
    deadline: Instant) -> Result<CapturedProduct> {
    complete(report, snapshots[0], snapshots[1])?;
    captured(report.clone(), snapshots, projects, stored(snapshots[0], snapshots[1], deadline)?)
}

fn read_bytes(path: &Path, deadline: Instant) -> Result<Vec<u8>> {
    budget(deadline)?;
    let mut file = open_regular(path)?;
    let before = file.metadata()?;
    ensure!(before.len() <= MAX_CAPSULE_BYTES as u64, "capsule exceeds 128 MiB");
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 65536];
    loop {
        budget(deadline)?;
        let count = file.read(&mut chunk)?;
        if count == 0 { break; }
        ensure!(bytes.len() + count <= MAX_CAPSULE_BYTES, "capsule exceeds 128 MiB");
        bytes.extend_from_slice(&chunk[..count]);
    }
    ensure!(same_file_version(&before, &file.metadata()?) && same_file_version(&before, &fs::symlink_metadata(path)?),
        "capsule changed while reading");
    Ok(bytes)
}

struct Loaded { capsule: Capsule, original: Snapshot, candidate: Option<Snapshot> }
impl Loaded {
    fn candidate(&self) -> &Snapshot { self.candidate.as_ref().unwrap_or(&self.original) }
}

fn load(path: &Path, pin: Option<&str>, deadline: Instant) -> Result<Loaded> {
    if let Some(pin) = pin { ensure!(is_hash(pin), "expected capsule SHA-256 must be 64 lowercase hexadecimal characters"); }
    let bytes = read_bytes(path, deadline)?;
    let capsule: Capsule = serde_json::from_slice(&bytes).context("invalid product migration capsule")?;
    ensure!(serde_json::to_vec(&capsule)? == bytes, "product capsule is not canonical or contains unknown fields");
    ensure!(capsule.payload.schema_version == SCHEMA && is_hash(&capsule.payload.implementation_sha256),
        "unsupported product capsule schema");
    ensure!(is_hash(&capsule.content_sha256) && payload_hash(&capsule.payload)? == capsule.content_sha256,
        "product capsule content hash mismatch");
    if let Some(pin) = pin { ensure!(pin == capsule.content_sha256, "capsule does not match the independently trusted hash"); }
    let mut blobs = BTreeMap::new();
    let mut decoded_bytes = 0_usize;
    ensure!(capsule.payload.blobs.len() <= MAX_ENTRIES * 2, "too many capsule blobs");
    let mut previous = "";
    for blob in &capsule.payload.blobs {
        budget(deadline)?;
        ensure!(is_hash(&blob.sha256) && previous < blob.sha256.as_str(), "capsule blobs must be unique and sorted");
        previous = &blob.sha256;
        ensure!(blob.hex.len().is_multiple_of(2), "invalid capsule file encoding");
        decoded_bytes = decoded_bytes.checked_add(blob.hex.len() / 2).context("capsule size overflow")?;
        ensure!(decoded_bytes <= MAX_EXPANDED_BYTES, "capsule decoded bytes exceed 32 MiB");
        let decoded = hex::decode(&blob.hex)?;
        ensure!(hex::encode(&decoded) == blob.hex && hex::encode(Sha256::digest(&decoded)) == blob.sha256,
            "capsule file bytes or hash mismatch");
        blobs.insert(blob.sha256.clone(), decoded);
    }
    let mut used = BTreeSet::new();
    let mut expanded = 0;
    let mut metadata = 0;
    let original = restore_snapshot(&capsule.payload.original, &blobs, &mut used, &mut expanded, &mut metadata, deadline)?;
    let candidate = capsule.payload.candidate.as_ref().map(|s|
        restore_snapshot(s, &blobs, &mut used, &mut expanded, &mut metadata, deadline)).transpose()?;
    ensure!(used.len() == blobs.len(), "capsule contains unreferenced blobs");
    complete(&capsule.payload.expected, &original, candidate.as_ref().unwrap_or(&original))?;
    budget(deadline)?;
    Ok(Loaded { capsule, original, candidate })
}

/// Read-only schema dispatch. No recorded runtime is resolved. Each selected
/// reader independently validates its exact schema and canonical encoding;
/// replay/export still require a pin, so a file swap cannot change authority.
fn product_schema(path: &Path, deadline: Instant) -> Result<bool> {
    #[derive(Deserialize)]
    struct Schema { schema_version: String }
    #[derive(Deserialize)]
    struct Envelope { payload: Schema }
    let value: Envelope = serde_json::from_slice(&read_bytes(path, deadline)?)?;
    match value.payload.schema_version.as_str() {
        SCHEMA => Ok(true),
        super::super::SCHEMA => Ok(false),
        _ => anyhow::bail!("unsupported migration capsule schema"),
    }
}

pub fn inspect(path: &Path) -> Result<CapsuleSummary> {
    Ok(summary(&load(path, None, Instant::now() + TOTAL_TIMEOUT)?.capsule))
}

pub fn inspect_any(path: &Path) -> Result<CapsuleSummary> {
    if product_schema(path, Instant::now() + TOTAL_TIMEOUT)? { inspect(path) }
    else { super::super::inspect(path) }
}

pub fn export_any(path: &Path, pin: &str, destination: &Path) -> Result<ExportedInputs> {
    ensure!(is_hash(pin), "expected capsule SHA-256 must be 64 lowercase hexadecimal characters");
    // Validate the output before reading private inputs, for either format.
    output_destination(destination, &[])?;
    if product_schema(path, Instant::now() + TOTAL_TIMEOUT)? { export_inputs(path, pin, destination) }
    else { super::super::export_inputs(path, pin, destination) }
}

pub fn export_inputs(path: &Path, pin: &str, destination: &Path) -> Result<ExportedInputs> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let destination = output_destination(destination, &[])?;
    let loaded = load(path, Some(pin), deadline)?;
    budget(deadline)?;
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    let original = destination.join("original");
    let candidate = destination.join("candidate");
    loaded.original.stage(&original, deadline)?;
    loaded.candidate().stage(&candidate, deadline)?;
    ensure!(Snapshot::capture(&original, deadline)?.digest == loaded.original.digest
        && Snapshot::capture(&candidate, deadline)?.digest == loaded.candidate().digest,
        "exported product inputs differ from the capture");
    budget(deadline)?;
    let manifest = serde_json::json!({
        "schema_version": "franken-node/product-reproducer/v1",
        "content_sha256": loaded.capsule.content_sha256,
        "original_project": "original", "candidate_project": "candidate",
        "expected": loaded.capsule.payload.expected,
        "execution_performed": false, "environment_reproduced": false, "release_certification": false,
    });
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(destination.join("reproducer.json"))?;
    serde_json::to_writer_pretty(&mut file, &manifest)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::File::open(&destination)?.sync_all()?;
    Ok(ExportedInputs { schema_version: "franken-node/product-reproducer-export/v1".into(),
        verdict: "EXPORTED".into(), destination, capsule: summary(&loaded.capsule), execution_performed: false })
}

pub fn replay(path: &Path, pin: &str, native: &Path, bun: &Path, verify_fix: bool) -> Result<ReplayResult> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let loaded = load(path, Some(pin), deadline)?;
    let (node, native) = runtime_invocations(native)?;
    let bun = Invocation { executable: bun.canonicalize().context("resolve Bun executable")?, before: vec![], after: vec![] };
    reexecute(loaded, [&node, &bun, &native], verify_fix, deadline)
}

fn reexecute(loaded: Loaded, runtimes: [&Invocation; 3], verify_fix: bool, deadline: Instant) -> Result<ReplayResult> {
    let expected = &loaded.capsule.payload.expected;
    ensure!(loaded.capsule.payload.implementation_sha256 == implementation(), "product replay validator implementation changed");
    for runtime in runtimes {
        let metadata = fs::metadata(&runtime.executable)?;
        ensure!(metadata.is_file() && metadata.permissions().mode() & 0o111 != 0, "runtime must be an executable regular file");
    }
    let identities = [runtimes[0].identity(deadline)?, runtimes[1].identity(deadline)?, runtimes[2].identity(deadline)?];
    ensure!(same_runtime(&expected.node_runtime, &identities[0]) && same_runtime(&expected.bun_runtime, &identities[1]),
        "Node or Bun reference runtime identity changed");
    ensure!(verify_fix || same_runtime(&expected.native_runtime, &identities[2]),
        "native runtime identity changed; use explicit fix verification");
    if verify_fix {
        ensure!(expected.verdict == "FAIL" && expected.reference_failures == 0 && expected.reference_divergences == 0,
            "product fix verification requires a captured native failure with agreeing successful references");
    }
    let mut validation = product_oracle::execute(&loaded.original, loaded.candidate(), runtimes,
        identities.clone(), deadline, LEG_TIMEOUT, expected.filesystem_comparison)?;
    if ![&validation.node_runtime, &validation.bun_runtime, &validation.native_runtime].into_iter()
        .zip(&identities).all(|(actual, admitted)| same_runtime(admitted, actual)) {
        validation.errors.push("runtime identity changed between product replay admission and execution".into());
        validation.verdict = "ERROR".into();
    }
    let mismatched_tests = expected.cases.iter().enumerate().filter(|(index, before)|
        validation.cases.get(*index).is_none_or(|after| if verify_fix {
            before.node != after.node || before.bun != after.bun
        } else { *before != after })).map(|(_, row)| row.test.clone()).collect::<Vec<_>>();
    let verdict = if complete(&validation, &loaded.original, loaded.candidate()).is_err() { "ERROR" }
        else if verify_fix && !mismatched_tests.is_empty() { "REFERENCE_DRIFT" }
        else if verify_fix { if validation.verdict == "PASS" { "FIX_VERIFIED" } else { "FIX_NOT_VERIFIED" } }
        else if mismatched_tests.is_empty() { "REPRODUCED" } else { "DIVERGED" };
    Ok(ReplayResult { schema_version: "franken-node/product-migration-replay/v1".into(), verdict: verdict.into(),
        content_sha256: loaded.capsule.content_sha256.clone(), captured_verdict: expected.verdict.clone(),
        mismatched_tests, execution_performed: true, environment_reproduced: false, release_certification: false, validation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    // Deliberately use /bin/true as a second reference and /bin/false as the
    // failing candidate in these archive/orchestration tests. They are NOT Bun
    // or Franken implementations and establish no runtime compatibility.
    fn fixture(source: &str, filesystem: bool) -> (tempfile::TempDir, tempfile::TempDir, PathBuf, String) {
        let root = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        fs::write(root.path().join("case.test.js"), source).unwrap();
        let captured = capture_project(root.path(), None, Path::new("/bin/false"), Path::new("/bin/true"), filesystem).unwrap();
        let path = out.path().join("capsule.json");
        let summary = captured.write_capsule(&path).unwrap();
        (root, out, path, summary.content_sha256)
    }
    fn edit(path: &Path, mutate: impl FnOnce(&mut Capsule)) {
        let mut capsule: Capsule = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        mutate(&mut capsule);
        capsule.content_sha256 = payload_hash(&capsule.payload).unwrap();
        fs::write(path, serde_json::to_vec(&capsule).unwrap()).unwrap();
    }
    fn rerun(path: &Path, pin: &str, fix: bool) -> ReplayResult {
        replay(path, pin, Path::new(if fix { "/bin/true" } else { "/bin/false" }), Path::new("/bin/true"), fix).unwrap()
    }

    #[test]
    fn complete_failure_round_trips_and_replays_original_not_later_source_bytes() {
        let (root, _out, path, pin) = fixture("globalThis.answer = 42;", true);
        let before = fs::read(&path).unwrap();
        fs::write(root.path().join("case.test.js"), "throw new Error('later source');").unwrap();
        let inspected = inspect_any(&path).unwrap();
        assert_eq!(inspected.schema_version, SCHEMA);
        assert_eq!(inspected.captured_verdict, "FAIL");
        assert!(!inspected.execution_performed);
        let replayed = rerun(&path, &pin, false);
        assert_eq!(replayed.verdict, "REPRODUCED");
        assert_eq!(replayed.validation.verdict, "FAIL");
        assert!(replayed.validation.cases[0].bun.is_some());
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn reference_disagreement_is_replayable_but_cannot_authorize_fix_verification() {
        let (_root, _out, path, pin) = fixture("console.log('Node differs from the deliberate empty-output reference');", true);
        assert_eq!(inspect(&path).unwrap().captured_verdict, "INCONCLUSIVE");
        let replayed = rerun(&path, &pin, false);
        assert_eq!(replayed.verdict, "REPRODUCED");
        assert_eq!(replayed.validation.reference_divergences, 1);
        assert!(replay(&path, &pin, Path::new("/bin/true"), Path::new("/bin/true"), true).is_err());
    }

    #[test]
    fn changed_candidate_is_allowed_only_for_explicit_fix_with_both_stable_references() {
        let (_root, _out, path, pin) = fixture("globalThis.answer = 42;", true);
        assert!(replay(&path, &pin, Path::new("/bin/true"), Path::new("/bin/true"), false).is_err());
        let result = rerun(&path, &pin, true);
        assert_eq!(result.verdict, "FIX_VERIFIED");
        assert_eq!(result.validation.passed, 1);
        assert!(!result.environment_reproduced && !result.release_certification);
        assert!(replay(&path, &pin, Path::new("/bin/true"), Path::new("/bin/false"), true).is_err());
    }

    #[test]
    fn changed_reference_observations_cannot_be_hidden_by_a_current_pass() {
        let (root, out, _, _) = fixture("globalThis.answer = 42;", false);
        let marker = out.path().join("ambient");
        let source = format!("if(require('fs').existsSync({}))console.log('drift');", serde_json::to_string(&marker).unwrap());
        fs::write(root.path().join("case.test.js"), source).unwrap();
        let captured = capture_project(root.path(), None, Path::new("/bin/false"), Path::new("/bin/true"), false).unwrap();
        let path = out.path().join("drift.json");
        let pin = captured.write_capsule(&path).unwrap().content_sha256;
        fs::write(marker, "now exists").unwrap();
        assert_eq!(rerun(&path, &pin, true).verdict, "REFERENCE_DRIFT");
    }

    #[test]
    fn imported_bun_observations_classifications_and_counters_are_checked_independently() {
        let (_root, _out, path, _) = fixture("globalThis.answer = 42;", true);
        let original = fs::read(&path).unwrap();
        for mutate in [
            (|c: &mut Capsule| c.payload.expected.cases[0].bun = None) as fn(&mut Capsule),
            |c| c.payload.expected.cases[0].bun.as_mut().unwrap().stdout.sha256 = "0".repeat(64),
            |c| c.payload.expected.cases[0].bun.as_mut().unwrap().workspace_delta = None,
            |c| c.payload.expected.reference_divergences = 1,
            |c| c.payload.expected.cases[0].outcome = CaseOutcome::Match,
            |c| c.payload.expected.cases[0].divergences.clear(),
            |c| c.payload.expected.distinct_reference_binaries = false,
            |c| c.payload.expected.filesystem_exclusions.push("**/*".into()),
            |c| c.payload.expected.skipped = 1,
        ] {
            fs::write(&path, &original).unwrap();
            edit(&path, mutate);
            assert!(inspect(&path).is_err());
        }
    }

    #[test]
    fn wrong_pin_unknown_fields_bad_paths_and_symlinks_are_refused_without_execution() {
        let (_root, out, path, pin) = fixture("globalThis.answer = 42;", true);
        let original = fs::read(&path).unwrap();
        assert!(replay(&path, &"0".repeat(64), Path::new("/absent/native"), Path::new("/absent/bun"), false)
            .unwrap_err().to_string().contains("trusted hash"));
        let alias = out.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(inspect_any(&alias).is_err());
        edit(&path, |c| c.payload.original.entries[0].path = "../escape.js".into());
        assert!(inspect(&path).is_err());
        fs::write(&path, &original).unwrap();
        let mut raw: serde_json::Value = serde_json::from_slice(&original).unwrap();
        raw["payload"]["expected"]["ignore_bun"] = true.into();
        fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
        assert!(inspect(&path).is_err());
        fs::write(&path, original).unwrap();
        assert_eq!(inspect(&path).unwrap().content_sha256, pin);
    }

    #[test]
    fn offline_export_keeps_distinct_candidates_and_all_three_expected_observations() {
        let (root, out, _, _) = fixture("globalThis.answer = 42;", true);
        let candidate = tempfile::tempdir().unwrap();
        fs::write(candidate.path().join("case.test.js"), "globalThis.answer = 43;").unwrap();
        let captured = capture_project(root.path(), Some(candidate.path()), Path::new("/bin/false"), Path::new("/bin/true"), true).unwrap();
        let path = out.path().join("distinct.json");
        let pin = captured.write_capsule(&path).unwrap().content_sha256;
        let destination = out.path().join("fixture");
        let exported = export_any(&path, &pin, &destination).unwrap();
        assert!(!exported.execution_performed);
        assert_ne!(exported.capsule.input_sha256, exported.capsule.candidate_input_sha256);
        assert_eq!(fs::read_to_string(destination.join("candidate/case.test.js")).unwrap(), "globalThis.answer = 43;");
        let manifest: serde_json::Value = serde_json::from_slice(&fs::read(destination.join("reproducer.json")).unwrap()).unwrap();
        assert_eq!(manifest["expected"]["cases"], serde_json::to_value(&captured.report.cases).unwrap());
        assert_eq!(fs::metadata(&destination).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(export_any(&path, &pin, &destination).is_err());
    }

    #[test]
    fn incomplete_execution_keeps_evidence_but_never_publishes_a_product_capsule() {
        let root = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        fs::write(root.path().join("case.test.js"), "process.stdout.write('x'.repeat(17*1024*1024));").unwrap();
        let captured = capture_project(root.path(), None, Path::new("/bin/false"), Path::new("/bin/true"), true).unwrap();
        assert_eq!(captured.report.verdict, "ERROR");
        assert!(captured.report.cases[0].bun.is_some());
        let path = out.path().join("incomplete.json");
        assert!(captured.write_capsule(&path).unwrap_err().to_string().contains("not replayable"));
        assert!(!path.exists());
    }
}
