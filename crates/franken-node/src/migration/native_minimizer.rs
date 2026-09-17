//! Execution-backed reduction of a pinned native migration capsule.
//!
//! Only selected source bytes may change. Every accepted candidate preserves
//! ALL recorded case observations in repeated full-suite runs. Fresh final
//! confirmation is mandatory even after the search budget is exhausted.
//! Reduced capsules use the ordinary replay format; reduction is not a fix,
//! a global-minimum proof, environmental replay, or an execution sandbox.

use super::{
    Blob, Capsule, CapsuleSummary, EntryData, Invocation, Loaded, Payload, SCHEMA,
    Snapshot, SuiteReport, MAX_CAPSULE_BYTES, LEG_TIMEOUT, budget, complete_report,
    execute_suite_pair, implementation_hash, load, output_destination, payload_hash,
    relative_path, runtime_invocations, same_runtime, store_snapshot, summary,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_SOURCE_FILES: usize = 16;
const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_SOURCE_LINES: usize = 4096;

#[derive(Debug, Clone)]
pub struct Options {
    /// Empty selects the failing test entrypoints, never every dependency.
    pub source_files: Vec<String>,
    /// Full-suite executions, including initial and final confirmations.
    pub max_executions: usize,
    pub seconds: u64,
    pub confirmations: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self { source_files: Vec::new(), max_executions: 128, seconds: 120, confirmations: 2 }
    }
}

impl Options {
    pub fn validate(&self) -> Result<()> {
        ensure!((2..=8).contains(&self.confirmations), "reduction confirmations must be between 2 and 8");
        ensure!((2 * self.confirmations..=4096).contains(&self.max_executions),
            "reduction execution budget must reserve initial/final confirmations and not exceed 4096");
        ensure!((1..=3600).contains(&self.seconds), "reduction time budget must be between 1 and 3600 seconds");
        ensure!(self.source_files.len() <= MAX_SOURCE_FILES, "select at most 16 reduction source files");
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLeg { Shared, Original, Candidate }

#[derive(Debug, Clone, Serialize)]
pub struct SourceSelection {
    pub leg: SourceLeg,
    pub path: PathBuf,
}

#[derive(Debug, Default, Serialize)]
pub struct Statistics {
    pub executions: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub unresolved: usize,
    pub cache_hits: usize,
    pub budget_exhausted: Option<String>,
    pub last_unresolved: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MinimizationReport {
    pub schema_version: String,
    pub verdict: String,
    pub parent_content_sha256: String,
    pub content_sha256: String,
    pub reducer_sha256: String,
    pub selected_sources: Vec<SourceSelection>,
    pub original_source_bytes: usize,
    pub reduced_source_bytes: usize,
    pub confirmations: usize,
    pub search_complete: bool,
    pub statistics: Statistics,
    pub execution_performed: bool,
    pub environment_reproduced: bool,
    pub release_certification: bool,
    pub validation: SuiteReport,
}

/// Deliberately not Debug/Serialize: the private archive contains source bytes.
pub struct MinimizedRun {
    pub report: MinimizationReport,
    capsule: Capsule,
}

impl MinimizedRun {
    /// Only available after fresh final confirmation. Never overwrite the seed.
    /// An I/O error can leave a partial new file, never a successful publication.
    pub fn write_capsule(&self, path: &Path) -> Result<CapsuleSummary> {
        let path = output_destination(path, &[])?;
        let encoded = serde_json::to_vec(&self.capsule)?;
        ensure!(encoded.len() <= MAX_CAPSULE_BYTES, "reduced capsule exceeds 128 MiB");
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        let mut result = summary(&self.capsule);
        result.execution_performed = true;
        Ok(result)
    }
}

/// Call only after explicit permission to execute trusted captured code. The
/// content pin must come from an independent trusted channel, not inspection
/// of an unfamiliar archive. Runtime commands always come from local selection.
pub fn minimize(path: &Path, expected_sha256: &str, native: &Path, options: &Options) -> Result<MinimizedRun> {
    options.validate()?;
    let started = Instant::now();
    let loaded = load(path, Some(expected_sha256), started + Duration::from_secs(options.seconds))?;
    require_seed(&loaded.capsule.payload.expected)?;
    // Validate source selections before even resolving runtime executables.
    selections(&loaded.original, loaded.candidate.as_ref(), &loaded.capsule.payload.expected, options)?;
    let (reference, native) = runtime_invocations(native)?;
    minimize_loaded(loaded, &reference, &native, options, started)
}

fn require_seed(report: &SuiteReport) -> Result<()> {
    ensure!(report.verdict == "FAIL", "reduction requires a captured failing migration");
    ensure!(report.cases.iter().all(|row| row.reference.as_ref().is_some_and(|run|
        run.exit_code == Some(0) && run.signal.is_none()) && row.native.as_ref().is_some_and(|run|
        run.exit_code.is_some_and(|code| code >= 0) && run.signal.is_none())),
        "reduction requires successful reference runs and ordinary, non-signal candidate exits");
    Ok(())
}

fn source<'a>(snapshot: &'a Snapshot, path: &Path) -> Result<&'a [u8]> {
    let entry = snapshot.entries.get(path).context("reduction source is missing from captured inputs")?;
    let EntryData::File(bytes) = &entry.data else {
        anyhow::bail!("reduction sources must be regular captured files, not links or directories");
    };
    Ok(bytes)
}

fn selections(original: &Snapshot, candidate: Option<&Snapshot>, expected: &SuiteReport,
    options: &Options) -> Result<Vec<SourceSelection>> {
    let paths = if options.source_files.is_empty() {
        expected.cases.iter().filter(|row| row.status == "FAIL").map(|row| row.test.clone()).collect()
    } else { options.source_files.clone() };
    select_sources(original, candidate, paths)
}

/// Shared source policy. The caller chooses the default failing-case identities
/// from its own evidence schema; the source and path rules never depend on it.
pub(super) fn select_sources(original: &Snapshot, candidate: Option<&Snapshot>,
    paths: Vec<String>) -> Result<Vec<SourceSelection>> {
    ensure!(!paths.is_empty() && paths.len() <= MAX_SOURCE_FILES, "select between 1 and 16 reduction source files");
    let mut unique = BTreeSet::new();
    for name in paths {
        let path = relative_path(&name)?;
        ensure!(!super::super::excluded_from_discovery(&path)
            && !path.components().any(|part| part.as_os_str() == ".franken-rewrite"),
            "dependencies, backups and reserved metadata cannot be reduction targets");
        ensure!(path.extension().and_then(|extension| extension.to_str())
            .is_some_and(|extension| ["js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx"].contains(&extension)),
            "reduction targets must be explicit JS/TS sources, not configuration");
        ensure!(unique.insert(path), "duplicate reduction source file");
    }
    let mut result = Vec::new();
    for (leg, snapshot) in if let Some(candidate) = candidate {
        vec![(SourceLeg::Original, original), (SourceLeg::Candidate, candidate)]
    } else { vec![(SourceLeg::Shared, original)] } {
        for path in &unique {
            let bytes = source(snapshot, path)?;
            ensure!(bytes.len() <= MAX_SOURCE_BYTES && line_ranges(bytes).len() <= MAX_SOURCE_LINES,
                "reduction source exceeds the 1 MiB/4096 line bound");
            std::str::from_utf8(bytes).context("reduction sources must be valid UTF-8")?;
            result.push(SourceSelection { leg, path: path.clone() });
        }
    }
    Ok(result)
}

pub(super) struct Inputs {
    pub(super) original: Snapshot,
    pub(super) candidate: Option<Snapshot>,
}
impl Inputs {
    pub(super) fn candidate(&self) -> &Snapshot { self.candidate.as_ref().unwrap_or(&self.original) }
    fn selected(&self, target: &SourceSelection) -> &Snapshot {
        match target.leg {
            SourceLeg::Shared | SourceLeg::Original => &self.original,
            SourceLeg::Candidate => self.candidate(),
        }
    }
    pub(super) fn bytes(&self, targets: &[SourceSelection]) -> Result<usize> {
        targets.iter().try_fold(0_usize, |sum, target|
            Ok(sum + source(self.selected(target), &target.path)?.len()))
    }
    fn replacing(&self, target: &SourceSelection, bytes: Vec<u8>) -> Result<Self> {
        let mut original = self.original.entries.clone();
        let mut candidate = self.candidate.as_ref().map(|s| s.entries.clone());
        let entries = match target.leg {
            SourceLeg::Shared | SourceLeg::Original => &mut original,
            SourceLeg::Candidate => candidate.as_mut().context("candidate source tree missing")?,
        };
        let entry = entries.get_mut(&target.path).context("reduction target disappeared")?;
        ensure!(matches!(entry.data, EntryData::File(_)), "nonregular reduction target");
        entry.data = EntryData::File(bytes);
        Ok(Self { original: Snapshot::from_entries(original), candidate: candidate.map(Snapshot::from_entries) })
    }
    fn key(&self) -> (String, String) { (self.original.digest.clone(), self.candidate().digest.clone()) }
}

/// Complete observations may prove acceptance or rejection. An unresolved run
/// proves neither. Fatal identity/invariant errors use Result::Err instead.
pub(super) enum Measurement<R> { Complete(R), Unresolved(anyhow::Error) }

/// Reserve final confirmation capacity independently of the evidence schema.
/// All callers share the same accounting, timeout and unresolved-run behavior.
pub(super) fn measure_with_budget<R>(options: &Options, timing: (Instant, Instant),
    statistics: &mut Statistics, final_check: bool,
    run: impl FnOnce(Instant) -> Result<Measurement<R>>) -> Result<Option<R>> {
    let (final_deadline, search_deadline) = timing;
    let limit = options.max_executions - if final_check { 0 } else { options.confirmations };
    let deadline = if final_check { final_deadline } else { search_deadline };
    let reason = if statistics.executions >= limit { Some("execution_budget") }
        else if Instant::now() >= deadline { Some("wall_time_budget") } else { None };
    if let Some(reason) = reason {
        ensure!(!final_check, "final reduction confirmation budget exhausted: {reason}");
        statistics.budget_exhausted = Some(reason.into());
        return Ok(None);
    }
    statistics.executions += 1;
    match run(deadline)? {
        Measurement::Complete(report) => Ok(Some(report)),
        Measurement::Unresolved(error) => {
            ensure!(!final_check, "final reduction confirmation failed: {error:#}");
            statistics.unresolved += 1;
            statistics.last_unresolved = Some(format!("{error:#}"));
            if Instant::now() >= deadline {
                statistics.budget_exhausted = Some("wall_time_budget".into());
            }
            Ok(None)
        }
    }
}

/// Runtime-specific execution/comparison, without a lossy common report type.
/// Reports stay in their original pair or product schema through final checks.
pub(super) trait ReductionOracle {
    type Report;
    fn measure(&mut self, inputs: &Inputs, final_check: bool) -> Result<Option<Self::Report>>;
    fn preserves(&self, report: &Self::Report) -> bool;
    fn statistics(&mut self) -> &mut Statistics;
}

struct Oracle<'a> {
    reference: &'a Invocation,
    native: &'a Invocation,
    expected: &'a SuiteReport,
    options: &'a Options,
    deadline: Instant,
    search_deadline: Instant,
    statistics: Statistics,
}

impl ReductionOracle for Oracle<'_> {
    type Report = SuiteReport;

    fn measure(&mut self, inputs: &Inputs, final_check: bool) -> Result<Option<SuiteReport>> {
        measure_with_budget(self.options, (self.deadline, self.search_deadline),
            &mut self.statistics, final_check, |deadline| {
                let report = match execute_suite_pair(&inputs.original, inputs.candidate(), self.reference, self.native,
                    deadline, LEG_TIMEOUT, self.expected.filesystem_comparison) {
                    Ok(report) => report,
                    Err(error) => return Ok(Measurement::Unresolved(error)),
                };
                ensure!(same_runtime(&self.expected.reference_runtime, &report.reference_runtime)
                    && same_runtime(&self.expected.native_runtime, &report.native_runtime),
                    "runtime identity changed during reduction");
                if let Err(error) = complete_report(&report, &inputs.original, inputs.candidate()) {
                    return Ok(Measurement::Unresolved(error));
                }
                Ok(Measurement::Complete(report))
            })
    }

    fn preserves(&self, report: &SuiteReport) -> bool {
        report.verdict == self.expected.verdict && report.cases == self.expected.cases
            && report.scope == self.expected.scope && report.filesystem_comparison == self.expected.filesystem_comparison
            && report.filesystem_exclusions == self.expected.filesystem_exclusions
    }

    fn statistics(&mut self) -> &mut Statistics { &mut self.statistics }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trial { Accept, Reject, Stop }

// Newline-delimited byte ranges preserve CRLF, UTF-8, and the final unterminated
// line. No recursive syntax walk or newline normalization changes guest input.
fn line_ranges(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' { ranges.push(start..index + 1); start = index + 1; }
    }
    if start < bytes.len() { ranges.push(start..bytes.len()); }
    ranges
}

fn reduce_lines(mut bytes: Vec<u8>, mut evaluate: impl FnMut(Vec<u8>) -> Result<Trial>) -> Result<bool> {
    let mut granularity: usize = 2;
    while !bytes.is_empty() {
        let ranges = line_ranges(&bytes);
        granularity = granularity.min(ranges.len());
        let mut accepted = false;
        for part in 0..granularity {
            let start = ranges[part * ranges.len() / granularity].start;
            let end = ranges[(part + 1) * ranges.len() / granularity - 1].end;
            let candidate = [&bytes[..start], &bytes[end..]].concat();
            match evaluate(candidate.clone())? {
                Trial::Accept => {
                    bytes = candidate;
                    accepted = true;
                    break;
                }
                Trial::Reject => {}
                Trial::Stop => return Ok(false),
            }
        }
        if accepted {
            granularity = granularity.saturating_sub(1).max(2);
        } else {
            if granularity == ranges.len() { return Ok(true); }
            granularity = (granularity * 2).min(ranges.len());
        }
    }
    Ok(true)
}

/// Shared line-complement search. All original cases must reproduce before
/// search, each acceptance is repeated, and fresh final evidence is mandatory.
/// Only complete rejections are cached, keyed by BOTH complete input hashes.
pub(super) fn reduce_inputs<O: ReductionOracle>(mut best: Inputs, targets: &[SourceSelection],
    confirmations: usize, oracle: &mut O) -> Result<(Inputs, O::Report, bool)> {
    ensure!((2..=8).contains(&confirmations), "invalid reduction confirmation count");
    for _ in 0..confirmations {
        let measured = oracle.measure(&best, false)?.context("initial reduction confirmation was incomplete")?;
        ensure!(oracle.preserves(&measured), "captured failure did not reproduce during initial confirmation");
    }
    let mut rejected = BTreeSet::new();
    let mut search_complete = true;
    'sweeps: loop {
        let before = best.bytes(targets)?;
        for target in targets {
            let bytes = source(best.selected(target), &target.path)?.to_vec();
            let completed = reduce_lines(bytes, |bytes| {
                let trial = best.replacing(target, bytes)?;
                let key = trial.key();
                if rejected.contains(&key) { oracle.statistics().cache_hits += 1; return Ok(Trial::Reject); }
                for _ in 0..confirmations {
                    let Some(measured) = oracle.measure(&trial, false)? else {
                        // Unresolved executions are never accepted or cached.
                        return Ok(if oracle.statistics().budget_exhausted.is_some() { Trial::Stop } else { Trial::Reject });
                    };
                    if !oracle.preserves(&measured) {
                        oracle.statistics().rejected += 1;
                        rejected.insert(key);
                        return Ok(Trial::Reject);
                    }
                }
                oracle.statistics().accepted += 1;
                best = trial;
                Ok(Trial::Accept)
            })?;
            if !completed { search_complete = false; break 'sweeps; }
        }
        if best.bytes(targets)? == before { break; }
    }
    let mut final_report = None;
    for _ in 0..confirmations {
        let measured = oracle.measure(&best, true)?.context("missing final reduction confirmation")?;
        ensure!(oracle.preserves(&measured), "reduced failure drifted during final confirmation; no capsule produced");
        final_report = Some(measured);
    }
    let validation = final_report.context("final reduction confirmation missing")?;
    Ok((best, validation, search_complete && oracle.statistics().unresolved == 0))
}

fn minimize_loaded(loaded: Loaded, reference: &Invocation, native: &Invocation,
    options: &Options, started: Instant) -> Result<MinimizedRun> {
    options.validate()?;
    let Loaded { capsule, original, candidate } = loaded;
    ensure!(capsule.payload.implementation_sha256 == implementation_hash(), "replay validator implementation changed");
    require_seed(&capsule.payload.expected)?;
    let targets = selections(&original, candidate.as_ref(), &capsule.payload.expected, options)?;
    let expected = capsule.payload.expected.clone();
    let parent_content_sha256 = capsule.content_sha256.clone();
    drop(capsule);
    let best = Inputs { original, candidate };
    let original_source_bytes = best.bytes(&targets)?;
    let duration = Duration::from_secs(options.seconds);
    let deadline = started + duration;
    ensure!(same_runtime(&expected.reference_runtime, &reference.identity(deadline)?)
        && same_runtime(&expected.native_runtime, &native.identity(deadline)?),
        "reduction requires the captured runtime identities and arguments");
    let mut oracle = Oracle { reference, native, expected: &expected, options, deadline,
        search_deadline: started + duration.mul_f64(0.8), statistics: Statistics::default() };
    let (best, validation, search_complete) = reduce_inputs(best, &targets, options.confirmations, &mut oracle)?;
    budget(deadline)?;
    let reduced_source_bytes = best.bytes(&targets)?;
    let mut blobs = BTreeMap::new();
    let mut expanded = 0;
    let mut metadata = 0;
    let original = store_snapshot(&best.original, &mut blobs, &mut expanded, &mut metadata, deadline)?;
    let candidate = best.candidate.as_ref().map(|snapshot|
        store_snapshot(snapshot, &mut blobs, &mut expanded, &mut metadata, deadline)).transpose()?;
    let payload = Payload { schema_version: SCHEMA.into(), implementation_sha256: implementation_hash(),
        original, candidate, blobs: blobs.into_iter().map(|(sha256, hex)| Blob { sha256, hex }).collect(),
        expected: validation.clone() };
    let content_sha256 = payload_hash(&payload)?;
    budget(deadline)?;
    let mut hash = Sha256::new();
    hash.update(b"franken-node/native-minimizer/v1\0");
    hash.update(include_bytes!("native_minimizer.rs"));
    hash.update(implementation_hash().as_bytes());
    let report = MinimizationReport { schema_version: "franken-node/native-minimization/v1".into(),
        verdict: if reduced_source_bytes < original_source_bytes { "REDUCED" } else { "UNCHANGED" }.into(),
        parent_content_sha256, content_sha256: content_sha256.clone(), reducer_sha256: hex::encode(hash.finalize()),
        selected_sources: targets, original_source_bytes, reduced_source_bytes, confirmations: options.confirmations,
        search_complete, statistics: oracle.statistics, execution_performed: true, environment_reproduced: false,
        release_certification: false, validation };
    Ok(MinimizedRun { report, capsule: Capsule { payload, content_sha256 } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(240) }
    fn node(candidate: bool) -> Invocation {
        Invocation { executable: super::super::super::node_on_path().unwrap(), before: vec![],
            after: if candidate { vec!["candidate".into()] } else { vec![] } }
    }
    fn put(root: &Path, path: &str, source: &str) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, source).unwrap();
    }
    fn seed(root: &Path, candidate: Option<&Path>) -> Loaded {
        let original = Snapshot::capture(root, deadline()).unwrap();
        let candidate = candidate.map(|p| Snapshot::capture(p, deadline()).unwrap());
        let expected = execute_suite_pair(&original, candidate.as_ref().unwrap_or(&original),
            &node(false), &node(true), deadline(), Duration::from_secs(5), true).unwrap();
        let mut blobs = BTreeMap::new();
        let mut expanded = 0;
        let mut metadata = 0;
        let stored_original = store_snapshot(&original, &mut blobs, &mut expanded, &mut metadata, deadline()).unwrap();
        let stored_candidate = candidate.as_ref().map(|s|
            store_snapshot(s, &mut blobs, &mut expanded, &mut metadata, deadline()).unwrap());
        let payload = Payload { schema_version: SCHEMA.into(), implementation_sha256: implementation_hash(),
            original: stored_original, candidate: stored_candidate,
            blobs: blobs.into_iter().map(|(sha256, hex)| Blob { sha256, hex }).collect(), expected };
        let content_sha256 = payload_hash(&payload).unwrap();
        Loaded { capsule: Capsule { payload, content_sha256 }, original, candidate }
    }
    fn options() -> Options { Options { seconds: 240, max_executions: 40, ..Options::default() } }
    fn failing_source() -> &'static str {
        "// removable setup\nconsole.log(process.argv.includes('candidate') ? 'wrong' : 'right');\n// removable tail\n"
    }

    #[test]
    fn complement_search_preserves_crlf_unicode_and_unterminated_line_bytes() {
        let text = "// α\r\nKEEP π\r\n// tail".as_bytes().to_vec();
        let mut best = text.clone();
        assert!(reduce_lines(text, |trial| {
            if trial.windows(b"KEEP".len()).any(|s| s == b"KEEP") { best = trial; Ok(Trial::Accept) }
            else { Ok(Trial::Reject) }
        }).unwrap());
        assert_eq!(best, "KEEP π\r\n".as_bytes());
        let mut calls = 0;
        assert!(reduce_lines(b"last".to_vec(), |trial| {
            calls += 1; assert!(trial.is_empty()); Ok(Trial::Accept)
        }).unwrap());
        assert_eq!(calls, 1);
        assert!(reduce_lines(Vec::new(), |_| panic!("empty source has no candidate")).unwrap());
    }

    #[test]
    fn stopping_search_never_adopts_the_unfinished_candidate() {
        let mut best = b"a\nb\nc\n".to_vec();
        let mut calls = 0;
        assert!(!reduce_lines(best.clone(), |trial| {
            calls += 1;
            if calls == 1 { best = trial; Ok(Trial::Accept) } else { Ok(Trial::Stop) }
        }).unwrap());
        assert_eq!(best, b"b\nc\n");
    }

    #[test]
    fn limits_are_checked_before_capsule_access_or_runtime_resolution() {
        for invalid in [Options { confirmations: 1, ..options() }, Options { confirmations: 9, ..options() },
            Options { max_executions: 3, ..options() }, Options { max_executions: 4097, ..options() },
            Options { seconds: 0, ..options() }, Options { seconds: 3601, ..options() },
            Options { source_files: vec!["x.js".into(); 17], ..options() }] {
            assert!(invalid.validate().is_err());
            assert!(minimize(Path::new("missing"), "invalid", Path::new("missing"), &invalid).is_err());
        }
        Options { max_executions: 4, ..Options::default() }.validate().unwrap();
    }

    // Real Node/Node processes exercise the production executor; these are not
    // measurements of native Franken compatibility or engine conformance.
    #[test]
    fn reduction_preserves_all_cases_and_produces_an_ordinary_replayable_capsule() {
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        put(root.path(), "case.test.js", failing_source());
        put(root.path(), "passing.test.js", "console.log('still passes');\n");
        put(root.path(), "config.json", "{\"preserved\":true}");
        let loaded = seed(root.path(), None);
        let parent = loaded.capsule.content_sha256.clone();
        let cases = loaded.capsule.payload.expected.cases.clone();
        let reduced = minimize_loaded(loaded, &node(false), &node(true), &options(), Instant::now()).unwrap();
        assert_eq!(reduced.report.verdict, "REDUCED");
        assert!(reduced.report.reduced_source_bytes < reduced.report.original_source_bytes);
        assert_eq!(reduced.report.validation.cases, cases);
        assert_eq!(reduced.report.validation.verdict, "FAIL");
        assert_eq!(reduced.report.parent_content_sha256, parent);
        assert!(reduced.report.statistics.accepted > 0);
        assert!(reduced.report.statistics.executions <= 40);
        assert!(!reduced.report.release_certification);
        assert_eq!(fs::read_to_string(root.path().join("case.test.js")).unwrap(), failing_source());
        let path = output.path().join("reduced.json");
        let summary = reduced.write_capsule(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(reduced.write_capsule(&path).is_err());
        let loaded = load(&path, Some(&summary.content_sha256), deadline()).unwrap();
        assert_eq!(source(&loaded.original, Path::new("config.json")).unwrap(), b"{\"preserved\":true}");
        let replayed = super::super::reexecute(loaded, &node(false), &node(true), false, deadline()).unwrap();
        assert_eq!(replayed.verdict, "REPRODUCED");
        assert_eq!(replayed.validation.cases, cases);
    }

    #[test]
    fn execution_budget_reserves_fresh_final_checks_and_reports_incomplete_search() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "case.test.js", failing_source());
        let reduced = minimize_loaded(seed(root.path(), None), &node(false), &node(true),
            &Options { max_executions: 4, ..options() }, Instant::now()).unwrap();
        assert_eq!(reduced.report.verdict, "UNCHANGED");
        assert_eq!(reduced.report.statistics.executions, 4);
        assert_eq!(reduced.report.statistics.accepted, 0);
        assert_eq!(reduced.report.statistics.budget_exhausted.as_deref(), Some("execution_budget"));
        assert!(!reduced.report.search_complete);
        assert_eq!(reduced.report.validation.verdict, "FAIL");
    }

    #[test]
    fn selected_supporting_sources_preserve_filesystem_effects_in_both_input_trees() {
        let original = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        for (root, value) in [(original.path(), "one"), (candidate.path(), "two")] {
            put(root, "scripts/check.js", "require('./helper.js');\n");
            put(root, "scripts/helper.js", &format!("// unused\nrequire('fs').writeFileSync('result','{value}');\n"));
            put(root, ".franken-node/migration-tests.json",
                r#"{"schema_version":"franken-node/migration-tests/v1","tests":["scripts/check.js"]}"#);
        }
        let loaded = seed(original.path(), Some(candidate.path()));
        let expected = loaded.capsule.payload.expected.cases.clone();
        let reduced = minimize_loaded(loaded, &node(false), &node(true),
            &Options { source_files: vec!["scripts/helper.js".into()], ..options() }, Instant::now()).unwrap();
        assert_eq!(reduced.report.verdict, "REDUCED");
        assert_eq!(reduced.report.selected_sources.len(), 2);
        assert_eq!(reduced.report.validation.cases, expected);
        assert_eq!(reduced.report.validation.cases[0].divergences, ["filesystem:workspace_delta_mismatch"]);
        assert!(!original.path().join("result").exists());
        assert!(!candidate.path().join("result").exists());
    }

    #[test]
    fn invalid_or_reserved_sources_cannot_reach_the_oracle() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "case.test.js", failing_source());
        put(root.path(), "config.json", "{}");
        put(root.path(), "node_modules/pkg/source.js", "// vendor");
        symlink("case.test.js", root.path().join("alias.js")).unwrap();
        let loaded = seed(root.path(), None);
        for files in [vec!["../case.test.js"], vec!["config.json"], vec!["alias.js"], vec!["missing.js"],
            vec!["node_modules/pkg/source.js"], vec!["case.test.js", "case.test.js"]] {
            let opts = Options { source_files: files.into_iter().map(str::to_owned).collect(), ..options() };
            assert!(selections(&loaded.original, None, &loaded.capsule.payload.expected, &opts).is_err());
        }
    }

    #[test]
    fn a_different_reproduced_failure_or_runtime_cannot_replace_the_seed() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "case.test.js", failing_source());
        let mut loaded = seed(root.path(), None);
        loaded.capsule.payload.expected.cases[0].native.as_mut().unwrap().stdout.sha256 = "0".repeat(64);
        assert!(minimize_loaded(loaded, &node(false), &node(true), &options(), Instant::now())
            .err().unwrap().to_string().contains("initial confirmation"));
        let loaded = seed(root.path(), None);
        assert!(minimize_loaded(loaded, &node(false), &node(false), &options(), Instant::now())
            .err().unwrap().to_string().contains("captured runtime"));
    }

    #[test]
    fn final_confirmation_is_fresh_and_refuses_late_ambient_drift() {
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let counter = external.path().join("counter");
        fs::write(&counter, "0").unwrap();
        put(root.path(), "case.test.js", &format!(
            "const fs=require('fs'); const p={}; const n=Number(fs.readFileSync(p,'utf8')); \
             fs.writeFileSync(p,String(n+1)); \
             console.log((process.argv.includes('candidate')?'native:':'reference:')+(n<6?'stable':'drift'));\n",
            serde_json::to_string(&counter).unwrap()));
        // Capture uses calls 0/1, initial confirmations use 2..5. No search
        // execution slots remain; the mandatory final run sees changed state.
        let loaded = seed(root.path(), None);
        let error = minimize_loaded(loaded, &node(false), &node(true),
            &Options { max_executions: 4, ..options() }, Instant::now()).err().unwrap();
        assert!(error.to_string().contains("final confirmation"), "{error:#}");
        assert_eq!(fs::read_to_string(counter).unwrap(), "8");
    }

    #[test]
    fn failed_search_dispatch_preserves_inputs_but_never_weakens_final_confirmation() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "case.test.js", failing_source());
        let Loaded { capsule, original, candidate } = seed(root.path(), None);
        let inputs = Inputs { original, candidate };
        let identity = inputs.key();
        let reference = node(false);
        let native = node(true);
        let absent = Invocation { executable: root.path().join("missing-runtime"), before: vec![], after: vec![] };
        let opts = options();
        let mut oracle = Oracle { reference: &absent, native: &native,
            expected: &capsule.payload.expected, options: &opts, deadline: deadline(),
            search_deadline: deadline(), statistics: Statistics::default() };
        assert!(oracle.measure(&inputs, false).unwrap().is_none());
        assert_eq!(oracle.statistics.executions, 1);
        assert_eq!(oracle.statistics.unresolved, 1);
        assert!(oracle.statistics.last_unresolved.as_deref().unwrap().contains("missing-runtime"));
        assert_eq!(oracle.statistics.accepted, 0);
        assert_eq!(oracle.statistics.rejected, 0);
        assert_eq!(inputs.key(), identity);
        oracle.reference = &reference;
        for _ in 0..opts.confirmations {
            let measured = oracle.measure(&inputs, true).unwrap().unwrap();
            assert!(oracle.preserves(&measured));
        }
        oracle.reference = &absent;
        assert!(oracle.measure(&inputs, true).unwrap_err().to_string().contains("final reduction confirmation failed"));
        assert_eq!(inputs.key(), identity);
    }

    #[test]
    fn exhausted_search_clock_keeps_final_confirmation_time_separate() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "case.test.js", failing_source());
        let Loaded { capsule, original, candidate } = seed(root.path(), None);
        let inputs = Inputs { original, candidate };
        let reference = node(false);
        let native = node(true);
        let opts = options();
        let mut oracle = Oracle { reference: &reference, native: &native,
            expected: &capsule.payload.expected, options: &opts, deadline: deadline(),
            search_deadline: Instant::now(), statistics: Statistics::default() };
        assert!(oracle.measure(&inputs, false).unwrap().is_none());
        assert_eq!(oracle.statistics.executions, 0);
        assert_eq!(oracle.statistics.budget_exhausted.as_deref(), Some("wall_time_budget"));
        for _ in 0..opts.confirmations {
            let measured = oracle.measure(&inputs, true).unwrap().unwrap();
            assert!(oracle.preserves(&measured));
        }
        assert_eq!(oracle.statistics.executions, opts.confirmations);
        oracle.deadline = Instant::now();
        assert!(oracle.measure(&inputs, true).unwrap_err().to_string().contains("final reduction confirmation budget exhausted"));
    }

    #[test]
    fn shared_budget_never_promotes_unresolved_or_fatal_measurements() {
        let options = Options { max_executions: 4, ..Options::default() };
        let mut statistics = Statistics::default();
        let timing = (deadline(), deadline());
        assert!(measure_with_budget::<()>(&options, timing, &mut statistics, false,
            |_| Ok(Measurement::Unresolved(anyhow::anyhow!("staging failed")))).unwrap().is_none());
        assert_eq!((statistics.executions, statistics.unresolved, statistics.accepted, statistics.rejected), (1, 1, 0, 0));
        let error = measure_with_budget::<()>(&options, timing, &mut statistics, false,
            |_| anyhow::bail!("runtime changed")).unwrap_err();
        assert!(error.to_string().contains("runtime changed"));
        assert_eq!(statistics.executions, 2);
        assert!(measure_with_budget::<()>(&options, timing, &mut statistics, false,
            |_| panic!("reserved final slots cannot be spent by search")).unwrap().is_none());
        for _ in 0..2 {
            assert!(measure_with_budget(&options, timing, &mut statistics, true,
                |_| Ok(Measurement::Complete(()))).unwrap().is_some());
        }
        assert_eq!(statistics.executions, 4);
        assert!(measure_with_budget::<()>(&options, timing, &mut statistics, true,
            |_| panic!("no capacity remains")).is_err());
    }
}
