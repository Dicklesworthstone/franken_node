//! Exact-input native migration replay. Capsules are private source archives,
//! not signatures, sandboxes, or captures of clocks/network/ambient authority.
//! Imported paths and links are validated before staging. Recorded commands
//! are evidence only: execution always uses locally selected invocations.

use super::{CapturedInputs, Entry, EntryData, Invocation, RuntimeIdentity, Snapshot, SuiteReport,
    MAX_ENTRIES, MAX_PATH_BYTES, TOTAL_TIMEOUT, LEG_TIMEOUT, budget, execute_suite_pair,
    matched_tests, open_regular, runtime_invocations, same_file_version, workspace_effects};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

#[path = "native_minimizer.rs"]
pub mod minimizer;

const SCHEMA: &str = "franken-node/native-migration-capsule/v1";
const MAX_CAPSULE_BYTES: usize = 128 * 1024 * 1024;
const MAX_EXPANDED_BYTES: usize = 32 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_LINK_HOPS: usize = 64;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Blob { sha256: String, hex: String }

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StoredData {
    Directory,
    File { sha256: String },
    Symlink { target: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEntry { path: String, mode: u32, data: StoredData }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSnapshot { input_sha256: String, entries: Vec<StoredEntry> }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    schema_version: String,
    implementation_sha256: String,
    original: StoredSnapshot,
    candidate: Option<StoredSnapshot>,
    blobs: Vec<Blob>,
    expected: SuiteReport,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capsule { payload: Payload, content_sha256: String }

#[derive(Debug, Serialize)]
pub struct CapsuleSummary {
    pub schema_version: String,
    pub content_sha256: String,
    pub input_sha256: String,
    pub candidate_input_sha256: String,
    pub captured_verdict: String,
    pub total_tests: usize,
    pub tests: Vec<String>,
    pub execution_performed: bool,
    pub environment_reproduced: bool,
    pub release_certification: bool,
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
    pub validation: SuiteReport,
}

/// No Debug/Serialize: do not accidentally log private captured project bytes.
pub struct CapturedRun {
    pub report: SuiteReport,
    capsule: Capsule,
    projects: [PathBuf; 2],
    unavailable: Option<String>,
}

fn is_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn implementation_hash() -> String {
    let mut hash = Sha256::new();
    hash.update(b"franken-node/native-replay-implementation/v1\0");
    for source in [include_str!("native_replay.rs"), include_str!("validation_suite.rs"),
        include_str!("smoke_supervisor.rs"), include_str!("workspace_effects.rs"),
        include_str!("test_inventory.rs")] {
        hash.update((source.len() as u64).to_le_bytes());
        hash.update(source.as_bytes());
    }
    hex::encode(hash.finalize())
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn payload_hash(payload: &Payload) -> Result<String> {
    let mut writer = HashWriter(Sha256::new());
    writer.0.update(b"franken-node/native-migration-capsule/v1\0");
    serde_json::to_writer(&mut writer, payload)?;
    Ok(hex::encode(writer.0.finalize()))
}

fn summary(capsule: &Capsule) -> CapsuleSummary {
    let report = &capsule.payload.expected;
    CapsuleSummary {
        schema_version: SCHEMA.into(), content_sha256: capsule.content_sha256.clone(),
        input_sha256: report.input_sha256.clone(), candidate_input_sha256: report.candidate_input_sha256.clone(),
        captured_verdict: report.verdict.clone(), total_tests: report.total_tests,
        tests: report.cases.iter().map(|row| row.test.clone()).collect(), execution_performed: false,
        environment_reproduced: false, release_certification: false,
    }
}

/// Resolve a create-only output outside the named input trees before execution.
/// Creation still uses create_new to refuse a final-path race or symlink.
pub fn output_destination(path: &Path, input_roots: &[&Path]) -> Result<PathBuf> {
    ensure!(fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "output already exists or cannot be inspected: {}", path.display());
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent = parent.canonicalize().context("resolve output parent")?;
    for root in input_roots {
        ensure!(!parent.starts_with(root.canonicalize()?), "output must be outside captured input trees");
    }
    Ok(parent.join(path.file_name().context("output filename missing")?))
}

impl CapturedRun {
    /// Publishes even a measured FAIL, but never an incomplete/ERROR run.
    /// Files are mode 0600 and create-only. An I/O error can leave a partial file.
    pub fn write_capsule(&self, path: &Path) -> Result<CapsuleSummary> {
        ensure!(self.unavailable.is_none(), "run is not replayable: {}",
            self.unavailable.as_deref().unwrap_or_default());
        let path = output_destination(path, &[&self.projects[0], &self.projects[1]])?;
        let encoded = serde_json::to_vec(&self.capsule)?;
        ensure!(encoded.len() <= MAX_CAPSULE_BYTES, "serialized capsule exceeds the 128 MiB limit");
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        let mut result = summary(&self.capsule);
        result.execution_performed = true;
        Ok(result)
    }
}

/// Capture BOTH input trees before executing. Archive limits are checked before
/// guest execution. The returned report survives failure to publish a capsule.
pub fn capture_project(project: &Path, migrated: Option<&Path>, native: &Path,
    compare_filesystem: bool) -> Result<CapturedRun> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let inputs = CapturedInputs::capture(project, migrated, deadline)?;
    let mut blobs = BTreeMap::new();
    let mut expanded = 0;
    let mut metadata = 0;
    let original = store_snapshot(&inputs.reference, &mut blobs, &mut expanded, &mut metadata, deadline)?;
    let candidate = inputs.candidate.as_ref().map(|snapshot|
        store_snapshot(snapshot, &mut blobs, &mut expanded, &mut metadata, deadline)).transpose()?;
    let report = inputs.execute(native, deadline, compare_filesystem)?;
    let unavailable = complete_report(&report, &inputs.reference, inputs.candidate_snapshot())
        .err().map(|error| format!("{error:#}"));
    let payload = Payload {
        schema_version: SCHEMA.into(), implementation_sha256: implementation_hash(), original, candidate,
        blobs: blobs.into_iter().map(|(sha256, hex)| Blob { sha256, hex }).collect(), expected: report.clone(),
    };
    let content_sha256 = payload_hash(&payload)?;
    Ok(CapturedRun { report, capsule: Capsule { payload, content_sha256 },
        projects: [inputs.reference_root, inputs.candidate_root], unavailable })
}

fn checked_link_target(target: &str) -> Result<&Path> {
    ensure!(!target.is_empty() && target.len() <= MAX_PATH_BYTES && !target.contains('\\')
        && !target.chars().any(char::is_control) && Path::new(target).is_relative(),
        "unsafe capsule symlink target");
    Ok(Path::new(target))
}

fn store_snapshot(snapshot: &Snapshot, blobs: &mut BTreeMap<String, String>, expanded: &mut usize,
    metadata: &mut usize, deadline: Instant) -> Result<StoredSnapshot> {
    let mut entries = Vec::new();
    for (path, entry) in &snapshot.entries {
        budget(deadline)?;
        let path = path.to_str().context("non-UTF-8 capsule path")?.to_owned();
        relative_path(&path)?;
        *metadata += path.len() + 128;
        let data = match &entry.data {
            EntryData::Directory => StoredData::Directory,
            EntryData::File(bytes) => {
                *expanded = expanded.checked_add(bytes.len()).context("capsule size overflow")?;
                ensure!(*expanded <= MAX_EXPANDED_BYTES, "capsule expanded inputs exceed 32 MiB");
                let sha256 = hex::encode(Sha256::digest(bytes));
                blobs.entry(sha256.clone()).or_insert_with(|| hex::encode(bytes));
                StoredData::File { sha256 }
            }
            EntryData::Link(target) => {
                let target = target.to_str().context("non-UTF-8 capsule link target")?.to_owned();
                check_link(Path::new(&path), checked_link_target(&target)?, &snapshot.entries, deadline)?;
                *metadata += target.len();
                StoredData::Symlink { target }
            }
        };
        ensure!(*metadata <= MAX_METADATA_BYTES, "capsule metadata exceeds 8 MiB");
        entries.push(StoredEntry { path, mode: entry.mode, data });
    }
    Ok(StoredSnapshot { input_sha256: snapshot.digest.clone(), entries })
}

fn relative_path(text: &str) -> Result<PathBuf> {
    let path = Path::new(text);
    ensure!(!text.is_empty() && text.len() <= MAX_PATH_BYTES && !text.contains('\\')
        && !text.chars().any(char::is_control)
        && path.components().all(|part| matches!(part, Component::Normal(_)))
        && path.components().map(|part| part.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/") == text
        && !path.components().any(|part| part.as_os_str() == ".git"), "unsafe capsule path: {text:?}");
    Ok(path.to_path_buf())
}

fn restore_snapshot(stored: &StoredSnapshot, blobs: &BTreeMap<String, Vec<u8>>, used: &mut BTreeSet<String>,
    expanded: &mut usize, metadata: &mut usize, deadline: Instant) -> Result<Snapshot> {
    ensure!(stored.entries.len() <= MAX_ENTRIES && is_hash(&stored.input_sha256), "invalid capsule snapshot");
    let mut entries = BTreeMap::new();
    let mut previous = None;
    for entry in &stored.entries {
        budget(deadline)?;
        let path = relative_path(&entry.path)?;
        ensure!(previous.as_ref().is_none_or(|old| old < &path), "capsule paths must be unique and sorted");
        previous = Some(path.clone());
        ensure!(entry.mode <= 0o777, "invalid capsule permissions");
        *metadata += entry.path.len() + 128;
        let data = match &entry.data {
            StoredData::Directory => EntryData::Directory,
            StoredData::File { sha256 } => {
                let bytes = blobs.get(sha256).context("capsule references missing file bytes")?;
                *expanded = expanded.checked_add(bytes.len()).context("capsule size overflow")?;
                ensure!(*expanded <= MAX_EXPANDED_BYTES, "capsule expanded inputs exceed 32 MiB");
                used.insert(sha256.clone());
                EntryData::File(bytes.clone())
            }
            StoredData::Symlink { target } => {
                let target_path = checked_link_target(target)?;
                *metadata += target.len();
                EntryData::Link(target_path.to_path_buf())
            }
        };
        ensure!(*metadata <= MAX_METADATA_BYTES, "capsule metadata exceeds 8 MiB");
        entries.insert(path, Entry { mode: entry.mode, data });
    }
    // Every nonroot parent must be an explicitly declared directory, never a
    // link or file. No imported entry may cause staging through a symlink.
    for path in entries.keys() {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            ensure!(entries.get(parent).is_some_and(|e| matches!(e.data, EntryData::Directory)),
                "capsule entry has an undeclared or non-directory parent");
        }
    }
    for (path, entry) in &entries {
        if let EntryData::Link(target) = &entry.data { check_link(path, target, &entries, deadline)?; }
    }
    let snapshot = Snapshot::from_entries(entries);
    ensure!(snapshot.digest == stored.input_sha256, "capsule snapshot digest mismatch");
    Ok(snapshot)
}

// Resolve against the imported tree, NOT the host filesystem. Handle links
// before subsequent '..' components, as real path resolution does.
fn check_link(path: &Path, target: &Path, entries: &BTreeMap<PathBuf, Entry>, deadline: Instant) -> Result<()> {
    let mut resolved = path.parent().unwrap_or(Path::new("")).to_path_buf();
    let mut pending: VecDeque<_> = target.components().map(|c| c.as_os_str().to_os_string()).collect();
    let mut hops = 0;
    while let Some(part) = pending.pop_front() {
        budget(deadline)?;
        if part == "." { continue; }
        if part == ".." { ensure!(resolved.pop(), "capsule symlink escapes its workspace"); continue; }
        ensure!(part != ".git", "capsule symlink enters excluded metadata");
        let next = resolved.join(&part);
        let entry = entries.get(&next).context("dangling capsule symlink")?;
        match &entry.data {
            EntryData::Link(target) => {
                hops += 1;
                ensure!(hops <= MAX_LINK_HOPS, "cyclic or excessive capsule symlink chain");
                for component in target.components().rev() { pending.push_front(component.as_os_str().to_os_string()); }
            }
            EntryData::Directory => resolved = next,
            EntryData::File(_) => {
                ensure!(pending.is_empty(), "capsule symlink traverses a file as a directory");
                resolved = next;
            }
        }
    }
    Ok(())
}

fn complete_report(report: &SuiteReport, original: &Snapshot, candidate: &Snapshot) -> Result<()> {
    let tests = matched_tests(original, candidate)?;
    ensure!(report.schema_version == "franken-node/native-validation-suite/v1"
        && !report.release_certification && report.input_sha256 == original.digest
        && report.candidate_input_sha256 == candidate.digest, "capsule measurement identity mismatch");
    let scope = if report.filesystem_comparison { "captured-test-process-and-workspace-delta" }
        else { "captured-test-process-stdout-stderr-exit" };
    let exclusions = if report.filesystem_comparison { workspace_effects::EXCLUSIONS } else { &[] };
    ensure!(report.scope == scope && report.filesystem_exclusions.iter().map(String::as_str).eq(exclusions.iter().copied()),
        "capsule measurement scope mismatch");
    ensure!(report.total_tests == tests.len() && report.cases.len() == tests.len()
        && report.errored == 0 && report.skipped == 0 && report.errors.is_empty(), "incomplete capsule execution evidence");
    ensure!(is_hash(&report.reference_runtime.sha256) && is_hash(&report.native_runtime.sha256), "invalid runtime hashes");
    let mut failed = 0;
    for (test, row) in tests.iter().zip(&report.cases) {
        ensure!(test.to_str() == Some(row.test.as_str()) && row.errors.is_empty(), "capsule test inventory mismatch");
        let reference = row.reference.as_ref().context("missing reference evidence")?;
        let native = row.native.as_ref().context("missing native evidence")?;
        let mut divergences = Vec::new();
        for (name, run) in [("reference", reference), ("native", native)] {
            ensure!(run.exit_code.is_some() != run.signal.is_some(), "invalid process termination evidence");
            ensure!(is_hash(&run.stdout.sha256) && is_hash(&run.stderr.sha256)
                && run.stdout.bytes <= 16 * 1024 * 1024 && run.stderr.bytes <= 16 * 1024 * 1024,
                "invalid process stream evidence");
            ensure!(run.workspace_delta.is_some() == report.filesystem_comparison, "missing or unexpected workspace evidence");
            if let Some(delta) = &run.workspace_delta {
                ensure!(is_hash(&delta.sha256) && delta.changes.len() == delta.changed_paths.min(20)
                    && delta.details_truncated == (delta.changed_paths > 20), "invalid workspace delta summary");
            }
            if run.exit_code != Some(0) || run.signal.is_some() { divergences.push(format!("{name}:unsuccessful_exit")); }
        }
        if reference.stdout != native.stdout { divergences.push("stdout:byte_mismatch".into()); }
        if reference.stderr != native.stderr { divergences.push("stderr:byte_mismatch".into()); }
        if reference.workspace_delta != native.workspace_delta { divergences.push("filesystem:workspace_delta_mismatch".into()); }
        let status = if divergences.is_empty() { "PASS" } else { failed += 1; "FAIL" };
        ensure!(row.status == status && row.divergences == divergences, "capsule verdict disagrees with measured observations");
    }
    ensure!(report.failed == failed && report.passed == tests.len() - failed
        && report.verdict == if failed == 0 { "PASS" } else { "FAIL" }, "capsule summary disagrees with measured cases");
    Ok(())
}

struct Loaded { capsule: Capsule, original: Snapshot, candidate: Option<Snapshot> }
impl Loaded {
    fn candidate(&self) -> &Snapshot { self.candidate.as_ref().unwrap_or(&self.original) }
}

fn load(path: &Path, pin: Option<&str>, deadline: Instant) -> Result<Loaded> {
    budget(deadline)?;
    if let Some(pin) = pin { ensure!(is_hash(pin), "expected capsule SHA-256 must be 64 lowercase hexadecimal characters"); }
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
    let capsule: Capsule = serde_json::from_slice(&bytes).context("invalid native migration capsule")?;
    // The compact canonical representation also rejects unknown/duplicate data
    // silently ignored by nested report deserializers. No whitespace variants.
    ensure!(serde_json::to_vec(&capsule)? == bytes, "capsule is not canonical or contains unknown fields");
    ensure!(capsule.payload.schema_version == SCHEMA && is_hash(&capsule.payload.implementation_sha256), "unsupported capsule schema");
    ensure!(is_hash(&capsule.content_sha256) && payload_hash(&capsule.payload)? == capsule.content_sha256,
        "capsule content hash mismatch");
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
    let candidate = capsule.payload.candidate.as_ref().map(|stored|
        restore_snapshot(stored, &blobs, &mut used, &mut expanded, &mut metadata, deadline)).transpose()?;
    ensure!(used.len() == blobs.len(), "capsule contains unreferenced blobs");
    complete_report(&capsule.payload.expected, &original, candidate.as_ref().unwrap_or(&original))?;
    budget(deadline)?;
    Ok(Loaded { capsule, original, candidate })
}

#[derive(Debug, Serialize)]
pub struct ExportedInputs {
    pub schema_version: String,
    pub verdict: String,
    pub destination: PathBuf,
    pub capsule: CapsuleSummary,
    pub execution_performed: bool,
}

/// Restore inspectable original/candidate trees without running project code or
/// resolving any runtime. Require the independently trusted capsule identity.
/// The destination must not exist; private partial output can remain on error.
/// `reproducer.json` is written only after both restored identities are checked.
pub fn export_inputs(path: &Path, expected_sha256: &str, destination: &Path) -> Result<ExportedInputs> {
    use std::os::unix::fs::DirBuilderExt;

    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let destination = output_destination(destination, &[])?;
    let loaded = load(path, Some(expected_sha256), deadline)?;
    budget(deadline)?;
    fs::DirBuilder::new().mode(0o700).create(&destination)
        .context("create private reproducer directory without replacing existing output")?;
    let original = destination.join("original");
    let candidate = destination.join("candidate");
    loaded.original.stage(&original, deadline)?;
    loaded.candidate().stage(&candidate, deadline)?;
    ensure!(Snapshot::capture(&original, deadline)?.digest == loaded.original.digest
        && Snapshot::capture(&candidate, deadline)?.digest == loaded.candidate().digest,
        "exported project identity differs from captured inputs; reproducer is incomplete");
    budget(deadline)?;
    let manifest = serde_json::json!({
        "schema_version": "franken-node/native-reproducer/v1",
        "content_sha256": &loaded.capsule.content_sha256,
        "original_project": "original",
        "candidate_project": "candidate",
        "expected": &loaded.capsule.payload.expected,
        "execution_performed": false,
        "environment_reproduced": false,
        "release_certification": false,
    });
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(destination.join("reproducer.json"))?;
    serde_json::to_writer_pretty(&mut file, &manifest)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    // Flush directory entries, without claiming an atomic multi-file export.
    fs::File::open(&destination)?.sync_all()?;
    Ok(ExportedInputs { schema_version: "franken-node/native-reproducer-export/v1".into(),
        verdict: "EXPORTED".into(), destination, capsule: summary(&loaded.capsule), execution_performed: false })
}

/// Offline inspection never resolves a runtime or stages/executes project code.
pub fn inspect(path: &Path) -> Result<CapsuleSummary> {
    Ok(summary(&load(path, None, Instant::now() + TOTAL_TIMEOUT)?.capsule))
}

fn same_runtime(expected: &RuntimeIdentity, measured: &RuntimeIdentity) -> bool {
    expected.sha256 == measured.sha256 && expected.arguments_before_test == measured.arguments_before_test
        && expected.arguments_after_test.iter().map(|arg| {
            if arg == expected.executable.as_os_str() { measured.executable.as_os_str() } else { arg.as_os_str() }
        }).eq(measured.arguments_after_test.iter().map(|arg| arg.as_os_str()))
}

/// The caller must explicitly approve execution and obtain the pin through a
/// trusted channel. Never derive the execution pin from untrusted inspection.
pub fn replay(path: &Path, expected_sha256: &str, native: &Path, verify_fix: bool) -> Result<ReplayResult> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let loaded = load(path, Some(expected_sha256), deadline)?;
    let (reference, native) = runtime_invocations(native)?;
    reexecute(loaded, &reference, &native, verify_fix, deadline)
}

fn reexecute(loaded: Loaded, reference: &Invocation, native: &Invocation, verify_fix: bool,
    deadline: Instant) -> Result<ReplayResult> {
    let expected = &loaded.capsule.payload.expected;
    ensure!(loaded.capsule.payload.implementation_sha256 == implementation_hash(), "replay validator implementation changed");
    ensure!(same_runtime(&expected.reference_runtime, &reference.identity(deadline)?), "reference runtime identity changed");
    let native_identity = native.identity(deadline)?;
    ensure!(verify_fix || same_runtime(&expected.native_runtime, &native_identity), "native runtime identity changed; use explicit fix verification");
    if verify_fix {
        ensure!(expected.verdict == "FAIL" && expected.cases.iter().all(|row|
            row.reference.as_ref().is_some_and(|run| run.exit_code == Some(0) && run.signal.is_none())),
            "fix verification requires a captured failure with a successful reference for every case");
    }
    let mut validation = execute_suite_pair(&loaded.original, loaded.candidate(), reference, native,
        deadline, LEG_TIMEOUT, expected.filesystem_comparison)?;
    // The executor fingerprints again around execution. Its actual identities
    // must agree with admission too, not merely with its own final recheck.
    if !same_runtime(&expected.reference_runtime, &validation.reference_runtime)
        || !same_runtime(&native_identity, &validation.native_runtime) {
        validation.errors.push("runtime identity changed between replay admission and execution".into());
        validation.verdict = "ERROR".into();
    }
    let mismatched_tests = expected.cases.iter().enumerate().filter(|(index, before)|
        validation.cases.get(*index).is_none_or(|after|
            if verify_fix { before.reference != after.reference } else { *before != after }))
        .map(|(_, before)| before.test.clone()).collect::<Vec<_>>();
    let complete = complete_report(&validation, &loaded.original, loaded.candidate()).is_ok();
    let verdict = if !complete { "ERROR" }
        else if verify_fix && !mismatched_tests.is_empty() { "REFERENCE_DRIFT" }
        else if verify_fix { if validation.verdict == "PASS" { "FIX_VERIFIED" } else { "FIX_NOT_VERIFIED" } }
        else if mismatched_tests.is_empty() { "REPRODUCED" } else { "DIVERGED" };
    Ok(ReplayResult { schema_version: "franken-node/native-migration-replay/v1".into(),
        verdict: verdict.into(), content_sha256: loaded.capsule.content_sha256.clone(), captured_verdict: expected.verdict.clone(),
        mismatched_tests, execution_performed: true, environment_reproduced: false,
        release_certification: false, validation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::Duration;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(90) }
    fn write(root: &Path, name: &str, text: &str) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    fn node(after: &[&str]) -> Invocation {
        Invocation { executable: super::super::node_on_path().unwrap(), before: vec![],
            after: after.iter().map(|s| (*s).into()).collect() }
    }
    // Explicit real Node/Node invocations exercise replay, not native parity.
    fn fixture(source: &str) -> (tempfile::TempDir, tempfile::TempDir, PathBuf, String) {
        let root = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        write(root.path(), "case.test.js", source);
        let original = Snapshot::capture(root.path(), deadline()).unwrap();
        let expected = execute_suite_pair(&original, &original, &node(&[]), &node(&["candidate"]),
            deadline(), Duration::from_secs(5), true).unwrap();
        let mut blobs = BTreeMap::new();
        let stored = store_snapshot(&original, &mut blobs, &mut 0, &mut 0, deadline()).unwrap();
        let payload = Payload { schema_version: SCHEMA.into(), implementation_sha256: implementation_hash(),
            original: stored, candidate: None, blobs: blobs.into_iter().map(|(sha256, hex)| Blob { sha256, hex }).collect(), expected };
        let pin = payload_hash(&payload).unwrap();
        let capsule = Capsule { payload, content_sha256: pin.clone() };
        let path = out.path().join("capsule.json");
        fs::write(&path, serde_json::to_vec(&capsule).unwrap()).unwrap();
        (root, out, path, pin)
    }
    fn execute(path: &Path, pin: &str, fix: bool, native: Invocation) -> ReplayResult {
        reexecute(load(path, Some(pin), deadline()).unwrap(), &node(&[]), &native, fix, deadline()).unwrap()
    }
    fn edit(path: &Path, mutation: impl FnOnce(&mut Capsule)) {
        let mut capsule: Capsule = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        mutation(&mut capsule);
        capsule.content_sha256 = payload_hash(&capsule.payload).unwrap();
        fs::write(path, serde_json::to_vec(&capsule).unwrap()).unwrap();
    }

    #[test]
    fn capture_preserves_real_failure_and_private_capsule_without_editing_inputs() {
        let root = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        write(root.path(), "case.test.js", "console.log('reference');");
        let run = capture_project(root.path(), None, Path::new("/bin/false"), true).unwrap();
        assert_eq!(run.report.verdict, "FAIL");
        let path = out.path().join("failure.json");
        let archived = run.write_capsule(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(archived.captured_verdict, "FAIL");
        let replayed = replay(&path, &archived.content_sha256, Path::new("/bin/false"), false).unwrap();
        assert_eq!(replayed.verdict, "REPRODUCED");
        assert_eq!(replayed.validation.verdict, "FAIL");
        assert!(!replayed.release_certification);
        let original = fs::read(&path).unwrap();
        assert!(run.write_capsule(&path).is_err());
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn captured_bytes_not_the_later_source_tree_are_reexecuted() {
        let (root, _out, path, pin) = fixture("console.log(process.argv.includes('candidate')?'wrong':'right');");
        write(root.path(), "case.test.js", "throw new Error('later source');");
        let report = execute(&path, &pin, false, node(&["candidate"]));
        assert_eq!(report.verdict, "REPRODUCED");
        assert_eq!(report.validation.failed, 1);
        assert_eq!(fs::read_to_string(root.path().join("case.test.js")).unwrap(), "throw new Error('later source');");
    }

    #[test]
    fn offline_inspection_never_resolves_recorded_executable_paths() {
        let (_root, _out, path, _pin) = fixture("console.log('ok');");
        edit(&path, |capsule| {
            capsule.payload.expected.reference_runtime.executable = "/absent/reference".into();
            capsule.payload.expected.native_runtime.executable = "/absent/native".into();
        });
        let report = inspect(&path).unwrap();
        assert_eq!(report.total_tests, 1);
        assert!(!report.execution_performed);
        assert!(!report.environment_reproduced);
    }

    #[test]
    fn wrong_pin_and_tampered_expected_data_cannot_silently_pass() {
        let (_root, _out, path, pin) = fixture("console.log('ok');");
        assert!(load(&path, Some(&"0".repeat(64)), deadline()).is_err());
        edit(&path, |capsule| {
            let row = &mut capsule.payload.expected.cases[0];
            for leg in [&mut row.reference, &mut row.native] {
                leg.as_mut().unwrap().stdout.sha256 = "0".repeat(64);
            }
        });
        assert!(load(&path, Some(&pin), deadline()).is_err());
        let new_pin = inspect(&path).unwrap().content_sha256;
        // Even an explicitly trusted altered expected observation is rerun.
        assert_eq!(execute(&path, &new_pin, false, node(&["candidate"])).verdict, "DIVERGED");
    }

    #[test]
    fn changed_candidate_requires_explicit_fix_mode_and_stable_reference() {
        let (_root, _out, path, pin) = fixture("console.log(process.argv.includes('candidate')?'wrong':'right');");
        assert!(reexecute(load(&path, Some(&pin), deadline()).unwrap(), &node(&[]), &node(&[]), false, deadline()).is_err());
        let fixed = execute(&path, &pin, true, node(&[]));
        assert_eq!(fixed.verdict, "FIX_VERIFIED");
        assert_eq!(fixed.validation.verdict, "PASS");
        assert_eq!(execute(&path, &pin, true, node(&["candidate"])).verdict, "FIX_NOT_VERIFIED");
    }

    #[test]
    fn reference_drift_is_not_a_verified_fix_even_when_current_legs_agree() {
        let state = tempfile::NamedTempFile::new().unwrap();
        fs::write(state.path(), "before").unwrap();
        let source = format!("console.log(require('fs').readFileSync({},'utf8')+(process.argv.includes('candidate')?'bad':''));",
            serde_json::to_string(state.path()).unwrap());
        let (_root, _out, path, pin) = fixture(&source);
        fs::write(state.path(), "after").unwrap();
        let report = execute(&path, &pin, true, node(&[]));
        assert_eq!(report.validation.verdict, "PASS");
        assert_eq!(report.verdict, "REFERENCE_DRIFT");
        assert_eq!(report.mismatched_tests, ["case.test.js"]);
    }

    #[test]
    fn failed_reference_cannot_be_used_to_verify_a_fix() {
        let (_root, _out, path, pin) = fixture("process.exit(7);");
        assert!(reexecute(load(&path, Some(&pin), deadline()).unwrap(), &node(&[]), &node(&[]), true, deadline()).is_err());
    }

    #[test]
    fn imported_paths_and_missing_blobs_are_rejected_before_staging() {
        let (_root, _out, path, _pin) = fixture("console.log('ok');");
        let original = fs::read(&path).unwrap();
        for name in ["../outside.js", "/absolute.js", "./case.test.js", "a//b.js", ".git/config", "undeclared/case.test.js"] {
            fs::write(&path, &original).unwrap();
            edit(&path, |capsule| capsule.payload.original.entries[0].path = name.into());
            assert!(inspect(&path).is_err(), "{name}");
        }
        fs::write(&path, original).unwrap();
        edit(&path, |capsule| capsule.payload.blobs.clear());
        assert!(inspect(&path).is_err());
    }

    #[test]
    fn symlink_resolution_is_contained_and_understands_intermediate_links() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "dir/value", "original");
        write(root.path(), "case.test.js", "console.log(require('fs').readFileSync('alias','utf8'));");
        symlink("dir/value", root.path().join("middle")).unwrap();
        symlink("middle", root.path().join("alias")).unwrap();
        let snapshot = Snapshot::capture(root.path(), deadline()).unwrap();
        for (path, entry) in &snapshot.entries {
            if let EntryData::Link(target) = &entry.data { check_link(path, target, &snapshot.entries, deadline()).unwrap(); }
        }
        for target in ["../escape", "missing", "alias/child", "dir/value/.."] {
            assert!(check_link(Path::new("alias"), Path::new(target), &snapshot.entries, deadline()).is_err());
        }
        let mut entries = snapshot.entries.clone();
        entries.get_mut(Path::new("middle")).unwrap().data = EntryData::Link("alias".into());
        assert!(check_link(Path::new("alias"), Path::new("middle"), &entries, deadline()).is_err());
    }

    #[test]
    fn noncanonical_and_unknown_nested_fields_are_rejected() {
        let (_root, _out, path, _pin) = fixture("console.log('ok');");
        let original = fs::read(&path).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["payload"]["expected"]["ignored_field"] = true.into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(inspect(&path).is_err());
        let mut spaced = original;
        spaced.push(b'\n');
        fs::write(&path, spaced).unwrap();
        assert!(inspect(&path).is_err());
    }

    #[test]
    fn changed_validator_and_incomplete_reports_never_authorize_replay() {
        let (_root, _out, path, _pin) = fixture("console.log('ok');");
        edit(&path, |capsule| capsule.payload.implementation_sha256 = "0".repeat(64));
        let pin = inspect(&path).unwrap().content_sha256;
        assert!(reexecute(load(&path, Some(&pin), deadline()).unwrap(), &node(&[]), &node(&["candidate"]), false, deadline()).is_err());
        edit(&path, |capsule| capsule.payload.expected.cases[0].native = None);
        assert!(inspect(&path).is_err());
    }

    #[test]
    fn capsule_paths_are_regular_bounded_files_and_outputs_are_create_only() {
        let (_root, out, path, _pin) = fixture("console.log('ok');");
        let alias = out.path().join("alias.json");
        symlink(&path, &alias).unwrap();
        assert!(inspect(&alias).is_err());
        assert!(output_destination(&alias, &[]).is_err());
        let huge = out.path().join("huge.json");
        fs::File::create(&huge).unwrap().set_len(MAX_CAPSULE_BYTES as u64 + 1).unwrap();
        assert!(inspect(&huge).is_err());
        assert!(load(&path, None, Instant::now()).is_err());
    }

    #[test]
    fn distinct_candidate_inputs_manifests_modes_and_links_round_trip() {
        let original = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        for root in [original.path(), candidate.path()] {
            write(root, "scripts/check.js", "console.log('reference');");
            write(root, ".franken-node/migration-tests.json",
                r#"{"schema_version":"franken-node/migration-tests/v1","tests":["scripts/check.js"]}"#);
            write(root, "data/value", "same dependency");
            symlink("data/value", root.join("alias")).unwrap();
            fs::set_permissions(root.join("scripts/check.js"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        write(candidate.path(), "scripts/check.js", "console.log('candidate');");
        let run = capture_project(original.path(), Some(candidate.path()), Path::new("/bin/false"), true).unwrap();
        let path = out.path().join("paired.json");
        let meta = run.write_capsule(&path).unwrap();
        assert_ne!(meta.input_sha256, meta.candidate_input_sha256);
        let loaded = load(&path, Some(&meta.content_sha256), deadline()).unwrap();
        assert_eq!(loaded.candidate().entries[Path::new("scripts/check.js")].mode, 0o755);
        assert!(matches!(&loaded.candidate().entries[Path::new("scripts/check.js")].data,
            EntryData::File(bytes) if bytes == b"console.log('candidate');"));
        assert!(matches!(&loaded.candidate().entries[Path::new("alias")].data,
            EntryData::Link(target) if target == Path::new("data/value")));
        assert_eq!(meta.tests, ["scripts/check.js"]);
        let result = replay(&path, &meta.content_sha256, Path::new("/bin/false"), false).unwrap();
        assert_eq!(result.verdict, "REPRODUCED");
    }

    #[test]
    fn unsupported_capture_paths_and_size_fail_before_runtime_resolution() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "case.test.js", "console.log('ok');");
        write(root.path(), "bad\nname", "unsupported capsule filename");
        let error = capture_project(root.path(), None, Path::new("/absent/native"), false).err().unwrap();
        assert!(error.to_string().contains("unsafe capsule path"));
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "case.test.js", "console.log('ok');");
        fs::File::create(root.path().join("big")).unwrap().set_len(MAX_EXPANDED_BYTES as u64 + 1).unwrap();
        let error = capture_project(root.path(), None, Path::new("/absent/native"), false).err().unwrap();
        assert!(error.to_string().contains("32 MiB"));
    }

    #[test]
    fn incomplete_execution_retains_measurement_but_cannot_publish_a_capsule() {
        let root = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        write(root.path(), "case.test.js", "process.stdout.write('x'.repeat(17*1024*1024));");
        let run = capture_project(root.path(), None, Path::new("/bin/false"), false).unwrap();
        assert_eq!(run.report.verdict, "ERROR");
        let path = out.path().join("incomplete.json");
        assert!(run.write_capsule(&path).is_err());
        assert!(!path.exists());
        assert!(!run.report.cases[0].errors.is_empty());
    }

    #[test]
    fn export_restores_both_captured_trees_and_permissions_without_editing_sources() {
        let original = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        let outputs = tempfile::tempdir().unwrap();
        for (root, value) in [(original.path(), "reference"), (candidate.path(), "candidate")] {
            write(root, "scripts/check.js", &format!("console.log('{value}');"));
            write(root, ".franken-node/migration-tests.json",
                r#"{"schema_version":"franken-node/migration-tests/v1","tests":["scripts/check.js"]}"#);
            write(root, "data/value", "captured data");
            symlink("data/value", root.join("alias")).unwrap();
            fs::set_permissions(root.join("scripts/check.js"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let captured = capture_project(original.path(), Some(candidate.path()), Path::new("/bin/false"), true).unwrap();
        let capsule = outputs.path().join("capsule.json");
        let identity = captured.write_capsule(&capsule).unwrap();
        let original_archive = fs::read(&capsule).unwrap();
        write(original.path(), "scripts/check.js", "later source");
        let destination = outputs.path().join("fixture");
        let exported = export_inputs(&capsule, &identity.content_sha256, &destination).unwrap();
        assert_eq!(exported.verdict, "EXPORTED");
        assert!(!exported.execution_performed && !exported.capsule.execution_performed);
        assert_eq!(fs::metadata(&destination).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::read_to_string(destination.join("original/scripts/check.js")).unwrap(), "console.log('reference');");
        assert_eq!(fs::read_to_string(destination.join("candidate/scripts/check.js")).unwrap(), "console.log('candidate');");
        assert_eq!(fs::read_link(destination.join("candidate/alias")).unwrap(), Path::new("data/value"));
        assert_eq!(fs::metadata(destination.join("original/scripts/check.js")).unwrap().permissions().mode() & 0o777, 0o755);
        let manifest_path = destination.join("reproducer.json");
        assert_eq!(fs::metadata(&manifest_path).unwrap().permissions().mode() & 0o777, 0o600);
        let manifest: serde_json::Value = serde_json::from_slice(&fs::read(manifest_path).unwrap()).unwrap();
        assert_eq!(manifest["expected"]["cases"], serde_json::to_value(&captured.report.cases).unwrap());
        assert_eq!(manifest["original_project"], "original");
        assert_eq!(manifest["candidate_project"], "candidate");
        assert_eq!(manifest["execution_performed"], false);
        assert_eq!(fs::read(capsule).unwrap(), original_archive);
        assert_eq!(fs::read_to_string(original.path().join("scripts/check.js")).unwrap(), "later source");
    }

    #[test]
    fn offline_export_does_not_require_available_or_current_runtime_implementations() {
        let (_root, outputs, path, _) = fixture("console.log('captured');");
        edit(&path, |capsule| {
            capsule.payload.implementation_sha256 = "0".repeat(64);
            capsule.payload.expected.reference_runtime.executable = "/absent/reference".into();
            capsule.payload.expected.native_runtime.executable = "/absent/candidate".into();
        });
        let pin = inspect(&path).unwrap().content_sha256;
        let exported = export_inputs(&path, &pin, &outputs.path().join("offline")).unwrap();
        assert!(!exported.execution_performed);
        assert_eq!(exported.capsule.captured_verdict, "PASS");
        assert!(exported.destination.join("original/case.test.js").is_file());
        assert!(exported.destination.join("candidate/case.test.js").is_file());
    }

    #[test]
    fn invalid_pin_and_existing_or_symlinked_exports_never_replace_data() {
        let (_root, outputs, path, pin) = fixture("console.log('captured');");
        let destination = outputs.path().join("fixture");
        assert!(export_inputs(&path, &"0".repeat(64), &destination).is_err());
        assert!(!destination.exists());
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("keep"), "preserve").unwrap();
        assert!(export_inputs(&path, &pin, &destination).is_err());
        let alias = outputs.path().join("alias");
        symlink(&destination, &alias).unwrap();
        assert!(export_inputs(&path, &pin, &alias).is_err());
        assert_eq!(fs::read_to_string(destination.join("keep")).unwrap(), "preserve");
        assert!(!destination.join("original").exists());
        assert!(!destination.join("reproducer.json").exists());
    }
}
