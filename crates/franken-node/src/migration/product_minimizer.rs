//! Minimize a pinned three-runtime failure without projecting away a reference.
//!
//! Node and Bun always share the original tree; only the native leg receives
//! a distinct candidate. The pair reducer supplies source validation, line and
//! syntax search, caching, budgets and mandatory fresh final confirmations.
//! This adapter supplies the real three-leg executor and product evidence.

use super::{Capsule, CapsuleSummary, CaseOutcome, Invocation, LEG_TIMEOUT, Loaded,
    MAX_CAPSULE_BYTES, Payload, ProductReport, SCHEMA, Snapshot, budget, complete,
    implementation, load, output_destination, payload_hash, product_oracle,
    runtime_invocations, same_runtime, stored, summary};
use super::super::super::{RuntimeIdentity, minimizer::{Inputs, Measurement, ReductionOracle,
    SourceSelection, Statistics, measure_with_budget, reduce_inputs, select_sources, syntax_fingerprint}};
pub use super::super::super::minimizer::Options;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Serialize)]
pub struct MinimizationReport {
    pub schema_version: String,
    pub verdict: String,
    pub captured_verdict: String,
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
    pub validation: ProductReport,
}

/// Private source material is deliberately not Debug/Serialize.
pub struct MinimizedProduct {
    pub report: MinimizationReport,
    capsule: Capsule,
}

impl MinimizedProduct {
    /// Only constructed after all fresh final confirmations. Create-only and
    /// owner-private; an I/O error may leave an incomplete new file.
    pub fn write_capsule(&self, path: &Path) -> Result<CapsuleSummary> {
        let path = output_destination(path, &[])?;
        let encoded = serde_json::to_vec(&self.capsule)?;
        ensure!(encoded.len() <= MAX_CAPSULE_BYTES, "reduced product capsule exceeds 128 MiB");
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        let mut result = summary(&self.capsule);
        result.execution_performed = true;
        Ok(result)
    }
}

/// Execute only explicitly approved trusted captured code, with an independent
/// content pin. A captured native failure OR successful-reference disagreement
/// can be reduced. Reduction is not fix verification or release certification.
pub fn minimize(path: &Path, pin: &str, native: &Path, bun: &Path,
    options: &Options) -> Result<MinimizedProduct> {
    options.validate()?;
    let started = Instant::now();
    let loaded = load(path, Some(pin), started + Duration::from_secs(options.seconds))?;
    require_seed(&loaded.capsule.payload.expected)?;
    selections(&loaded.original, loaded.candidate.as_ref(), &loaded.capsule.payload.expected, options)?;
    ensure!(loaded.capsule.payload.implementation_sha256 == implementation(),
        "product replay validator implementation changed");
    let (node, native) = runtime_invocations(native)?;
    let bun = Invocation { executable: bun.canonicalize().context("resolve Bun executable")?, before: vec![], after: vec![] };
    minimize_loaded(loaded, [&node, &bun, &native], options, started)
}

fn require_seed(report: &ProductReport) -> Result<()> {
    ensure!(matches!(report.verdict.as_str(), "FAIL" | "INCONCLUSIVE"),
        "product reduction requires a captured native failure or reference disagreement");
    ensure!(report.cases.iter().all(|row| {
        [&row.node, &row.bun].into_iter().all(|run| run.as_ref().is_some_and(|run|
            run.exit_code == Some(0) && run.signal.is_none()))
        && row.native.as_ref().is_some_and(|run|
            run.exit_code.is_some_and(|code| (0..=255).contains(&code)) && run.signal.is_none())
    }), "product reduction requires successful Node and Bun runs and ordinary non-signal native exits");
    Ok(())
}

fn selections(original: &Snapshot, candidate: Option<&Snapshot>, expected: &ProductReport,
    options: &Options) -> Result<Vec<SourceSelection>> {
    let paths = if options.source_files.is_empty() {
        expected.cases.iter().filter(|row| row.outcome != CaseOutcome::Match)
            .map(|row| row.test.clone()).collect()
    } else { options.source_files.clone() };
    select_sources(original, candidate, paths)
}

fn identities(runtimes: [&Invocation; 3], deadline: Instant) -> Result<[RuntimeIdentity; 3]> {
    Ok([runtimes[0].identity(deadline)?, runtimes[1].identity(deadline)?, runtimes[2].identity(deadline)?])
}

fn same_runtimes(expected: &ProductReport, actual: [&RuntimeIdentity; 3]) -> bool {
    [&expected.node_runtime, &expected.bun_runtime, &expected.native_runtime].into_iter()
        .zip(actual).all(|(before, after)| same_runtime(before, after))
}

struct Oracle<'a> {
    runtimes: [&'a Invocation; 3],
    expected: &'a ProductReport,
    options: &'a Options,
    deadline: Instant,
    search_deadline: Instant,
    statistics: Statistics,
}

impl ReductionOracle for Oracle<'_> {
    type Report = ProductReport;

    fn measure(&mut self, inputs: &Inputs, final_check: bool) -> Result<Option<ProductReport>> {
        measure_with_budget(self.options, (self.deadline, self.search_deadline),
            &mut self.statistics, final_check, |deadline| {
                // Every attempt fingerprints all three before dispatch. No
                // two-leg fallback or cached runtime identity is permitted.
                let identities = match identities(self.runtimes, deadline) {
                    Ok(identities) => identities,
                    Err(error) => return Ok(Measurement::Unresolved(error)),
                };
                ensure!(same_runtimes(self.expected, [&identities[0], &identities[1], &identities[2]]),
                    "runtime identity changed during product reduction");
                let report = match product_oracle::execute(&inputs.original, inputs.candidate(),
                    self.runtimes, identities, deadline, LEG_TIMEOUT, self.expected.filesystem_comparison) {
                    Ok(report) => report,
                    Err(error) => return Ok(Measurement::Unresolved(error)),
                };
                ensure!(same_runtimes(self.expected, [&report.node_runtime, &report.bun_runtime, &report.native_runtime]),
                    "runtime identity changed between product reduction admission and execution");
                if let Err(error) = complete(&report, &inputs.original, inputs.candidate()) {
                    return Ok(Measurement::Unresolved(error));
                }
                Ok(Measurement::Complete(report))
            })
    }

    fn preserves(&self, report: &ProductReport) -> bool {
        // ProductCase equality includes EVERY role's termination, streams,
        // filesystem summary and classification, including passing cases.
        report.verdict == self.expected.verdict && report.cases == self.expected.cases
            && report.schema_version == self.expected.schema_version && report.oracle == self.expected.oracle
            && report.scope == self.expected.scope && report.filesystem_comparison == self.expected.filesystem_comparison
            && report.filesystem_exclusions == self.expected.filesystem_exclusions
    }

    fn statistics(&mut self) -> &mut Statistics { &mut self.statistics }
}

fn minimize_loaded(loaded: Loaded, runtimes: [&Invocation; 3], options: &Options,
    started: Instant) -> Result<MinimizedProduct> {
    options.validate()?;
    let Loaded { capsule, original, candidate } = loaded;
    ensure!(capsule.payload.implementation_sha256 == implementation(), "product replay validator implementation changed");
    let expected = capsule.payload.expected.clone();
    complete(&expected, &original, candidate.as_ref().unwrap_or(&original))?;
    require_seed(&expected)?;
    let targets = selections(&original, candidate.as_ref(), &expected, options)?;
    let parent_content_sha256 = capsule.content_sha256.clone();
    drop(capsule);
    let inputs = Inputs { original, candidate };
    let original_source_bytes = inputs.bytes(&targets)?;
    let duration = Duration::from_secs(options.seconds);
    let deadline = started + duration;
    for runtime in runtimes {
        let metadata = fs::metadata(&runtime.executable)?;
        ensure!(metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            "product reduction runtime must be an executable regular file");
    }
    let admitted = identities(runtimes, deadline)?;
    ensure!(same_runtimes(&expected, [&admitted[0], &admitted[1], &admitted[2]]),
        "product reduction requires all captured runtime identities and arguments");
    let mut oracle = Oracle { runtimes, expected: &expected, options, deadline,
        search_deadline: started + duration.mul_f64(0.8), statistics: Statistics::default() };
    let (best, validation, search_complete) = reduce_inputs(inputs, &targets, options.confirmations,
        oracle.search_deadline, &mut oracle)?;
    budget(deadline)?;
    let reduced_source_bytes = best.bytes(&targets)?;
    let (original, candidate, blobs) = stored(&best.original, best.candidate(), deadline)?;
    let payload = Payload { schema_version: SCHEMA.into(), implementation_sha256: implementation(),
        original, candidate, blobs, expected: validation.clone() };
    let content_sha256 = payload_hash(&payload)?;
    let mut reducer = Sha256::new();
    reducer.update(b"franken-node/product-minimizer/v1\0");
    for source in [include_str!("product_minimizer.rs"), include_str!("native_minimizer.rs")] {
        reducer.update((source.len() as u64).to_le_bytes());
        reducer.update(source.as_bytes());
    }
    reducer.update(syntax_fingerprint().as_bytes());
    reducer.update(implementation().as_bytes());
    budget(deadline)?;
    let report = MinimizationReport { schema_version: "franken-node/product-minimization/v1".into(),
        verdict: if reduced_source_bytes < original_source_bytes { "REDUCED" } else { "UNCHANGED" }.into(),
        captured_verdict: expected.verdict.clone(), parent_content_sha256,
        content_sha256: content_sha256.clone(), reducer_sha256: hex::encode(reducer.finalize()),
        selected_sources: targets, original_source_bytes, reduced_source_bytes,
        confirmations: options.confirmations, search_complete, statistics: oracle.statistics,
        execution_performed: true, environment_reproduced: false, release_certification: false, validation };
    Ok(MinimizedProduct { report, capsule: Capsule { payload, content_sha256 } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{capture_project, export_inputs, inspect, replay, reexecute};
    use std::os::unix::fs::symlink;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(600) }
    fn options() -> Options { Options { seconds: 600, max_executions: 48, ..Options::default() } }
    fn put(root: &Path, name: &str, source: &str) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, source).unwrap();
    }
    fn invocation(path: &str) -> Invocation {
        Invocation { executable: Path::new(path).canonicalize().unwrap(), before: vec![], after: vec![] }
    }
    fn seed(root: &Path, candidate: Option<&Path>, runtimes: [&Invocation; 3]) -> Loaded {
        let original = Snapshot::capture(root, deadline()).unwrap();
        let candidate = candidate.map(|path| Snapshot::capture(path, deadline()).unwrap());
        let expected = product_oracle::execute(&original, candidate.as_ref().unwrap_or(&original), runtimes,
            identities(runtimes, deadline()).unwrap(), deadline(), Duration::from_secs(5), true).unwrap();
        complete(&expected, &original, candidate.as_ref().unwrap_or(&original)).unwrap();
        let (stored_original, stored_candidate, blobs) = stored(&original, candidate.as_ref().unwrap_or(&original), deadline()).unwrap();
        let payload = Payload { schema_version: SCHEMA.into(), implementation_sha256: implementation(),
            original: stored_original, candidate: stored_candidate, blobs, expected };
        let content_sha256 = payload_hash(&payload).unwrap();
        Loaded { capsule: Capsule { payload, content_sha256 }, original, candidate }
    }

    // /bin/true is an explicitly empty-output reference/candidate here, NOT a
    // Bun/Franken implementation. The separate executable integration runs real
    // Node and Bun. These tests exercise the shared production reducer/codec.
    #[test]
    fn reference_disagreement_reduces_and_replays_without_losing_passing_cases() {
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let original = "// α removable\r\nconsole.log('preserved');\r\n// tail";
        put(root.path(), "case.test.js", original);
        put(root.path(), "passing.test.js", "globalThis.answer = 42;");
        let capture = capture_project(root.path(), None, Path::new("/bin/true"), Path::new("/bin/true"), true).unwrap();
        assert_eq!(capture.report.verdict, "INCONCLUSIVE");
        assert_eq!(capture.report.passed, 1);
        let path = output.path().join("seed.json");
        let pin = capture.write_capsule(&path).unwrap().content_sha256;
        let seed_bytes = fs::read(&path).unwrap();
        put(root.path(), "case.test.js", "throw new Error('later input must not execute');");
        let reduced = minimize(&path, &pin, Path::new("/bin/true"), Path::new("/bin/true"), &options()).unwrap();
        assert_eq!(reduced.report.verdict, "REDUCED");
        assert_eq!(reduced.report.captured_verdict, "INCONCLUSIVE");
        assert_eq!(reduced.report.validation.cases, capture.report.cases);
        assert_eq!(reduced.report.selected_sources.len(), 1);
        assert!(reduced.report.reduced_source_bytes < reduced.report.original_source_bytes);
        assert_eq!(reduced.report.parent_content_sha256, pin);
        assert!(reduced.report.statistics.accepted > 0);
        assert!(!reduced.report.environment_reproduced && !reduced.report.release_certification);
        let result = output.path().join("reduced.json");
        let summary = reduced.write_capsule(&result).unwrap();
        assert_eq!(summary.schema_version, SCHEMA);
        assert_eq!(inspect(&result).unwrap().content_sha256, summary.content_sha256);
        assert_eq!(fs::metadata(&result).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(reduced.write_capsule(&result).is_err());
        let replayed = replay(&result, &summary.content_sha256, Path::new("/bin/true"), Path::new("/bin/true"), false).unwrap();
        assert_eq!(replayed.verdict, "REPRODUCED");
        assert_eq!(replayed.validation.cases, capture.report.cases);
        let export = export_inputs(&result, &summary.content_sha256, &output.path().join("fixture")).unwrap();
        assert_eq!(fs::read(export.destination.join("original/case.test.js")).unwrap(), b"console.log('preserved');\r\n");
        assert_eq!(fs::read(&path).unwrap(), seed_bytes);
        assert_eq!(fs::read_to_string(root.path().join("case.test.js")).unwrap(), "throw new Error('later input must not execute');");
    }

    #[test]
    fn native_failure_budget_keeps_all_reserved_final_runs() {
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        put(root.path(), "case.test.js", "// removable\nglobalThis.answer = 42;\n");
        let capture = capture_project(root.path(), None, Path::new("/bin/false"), Path::new("/bin/true"), true).unwrap();
        let path = output.path().join("seed.json");
        let pin = capture.write_capsule(&path).unwrap().content_sha256;
        let reduced = minimize(&path, &pin, Path::new("/bin/false"), Path::new("/bin/true"),
            &Options { max_executions: 4, ..options() }).unwrap();
        assert_eq!(reduced.report.verdict, "UNCHANGED");
        assert_eq!(reduced.report.validation.verdict, "FAIL");
        assert_eq!(reduced.report.statistics.executions, 4);
        assert_eq!(reduced.report.statistics.accepted, 0);
        assert_eq!(reduced.report.statistics.budget_exhausted.as_deref(), Some("execution_budget"));
        assert!(!reduced.report.search_complete);
        assert_eq!(reduced.report.validation.cases, capture.report.cases);
    }

    #[test]
    fn supporting_sources_reduce_independently_without_changing_workspace_effects() {
        let original = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        for (root, text) in [(original.path(), "original"), (candidate.path(), "candidate")] {
            put(root, "scripts/check.js", "require('./helper.js');\n");
            put(root, "scripts/helper.js", &format!("// remove\nrequire('fs').writeFileSync('result','{text}');\n"));
            put(root, ".franken-node/migration-tests.json",
                r#"{"schema_version":"franken-node/migration-tests/v1","tests":["scripts/check.js"]}"#);
            fs::set_permissions(root.join("scripts/helper.js"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let (node, _) = runtime_invocations(Path::new("/bin/false")).unwrap();
        let empty = invocation("/bin/true");
        // Actual Node executes both source trees; empty reference intentionally
        // disagrees. This is not a successful native compatibility measurement.
        let loaded = seed(original.path(), Some(candidate.path()), [&node, &empty, &node]);
        let expected = loaded.capsule.payload.expected.cases.clone();
        let reduced = minimize_loaded(loaded, [&node, &empty, &node],
            &Options { source_files: vec!["scripts/helper.js".into()], ..options() }, Instant::now()).unwrap();
        assert_eq!(reduced.report.verdict, "REDUCED");
        assert_eq!(reduced.report.validation.cases, expected);
        assert_eq!(reduced.report.selected_sources.len(), 2);
        let path = output.path().join("reduced.json");
        let pin = reduced.write_capsule(&path).unwrap().content_sha256;
        let export = export_inputs(&path, &pin, &output.path().join("export")).unwrap();
        for (tree, text) in [("original", "original"), ("candidate", "candidate")] {
            let source = export.destination.join(tree).join("scripts/helper.js");
            assert_eq!(fs::metadata(&source).unwrap().permissions().mode() & 0o777, 0o755);
            assert_eq!(fs::read_to_string(source).unwrap(), format!("require('fs').writeFileSync('result','{text}');\n"));
            assert!(!export.destination.join(tree).join("result").exists());
        }
        assert!(!original.path().join("result").exists());
        assert!(!candidate.path().join("result").exists());
        let loaded = load(&path, Some(&pin), deadline()).unwrap();
        assert_eq!(reexecute(loaded, [&node, &empty, &node], false, deadline()).unwrap().verdict, "REPRODUCED");
    }

    #[test]
    fn source_pin_and_runtime_preflight_cannot_launch_captured_code() {
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let marker = output.path().join("executions");
        put(root.path(), "case.test.js", &format!("require('fs').appendFileSync({},'x');",
            serde_json::to_string(&marker).unwrap()));
        put(root.path(), "config.json", "{}");
        put(root.path(), "node_modules/pkg/file.js", "// vendor");
        symlink("case.test.js", root.path().join("alias.js")).unwrap();
        let capture = capture_project(root.path(), None, Path::new("/bin/false"), Path::new("/bin/true"), true).unwrap();
        let path = output.path().join("seed.json");
        let pin = capture.write_capsule(&path).unwrap().content_sha256;
        let absent = Path::new("/absent/product-minimizer-runtime");
        assert!(minimize(&path, &"0".repeat(64), absent, absent, &options()).err().unwrap().to_string().contains("trusted hash"));
        for files in [vec!["../case.test.js"], vec!["config.json"], vec!["alias.js"], vec!["missing.js"],
            vec!["node_modules/pkg/file.js"], vec!["case.test.js", "case.test.js"]] {
            let opts = Options { source_files: files.into_iter().map(str::to_owned).collect(), ..options() };
            assert!(minimize(&path, &pin, absent, absent, &opts).is_err());
        }
        assert!(minimize(&path, &pin, Path::new("/bin/false"), Path::new("/bin/false"), &options())
            .err().unwrap().to_string().contains("captured runtime identities"));
        assert_eq!(fs::read_to_string(marker).unwrap(), "x");
        for invalid in [Options { confirmations: 1, ..options() }, Options { max_executions: 3, ..options() },
            Options { seconds: 0, ..options() }] {
            assert!(minimize(Path::new("absent-capsule"), "invalid", absent, absent, &invalid).is_err());
        }
    }

    #[test]
    fn passing_reference_failure_and_signal_seeds_are_not_reduction_evidence() {
        let root = tempfile::tempdir().unwrap();
        let (node, _) = runtime_invocations(Path::new("/bin/false")).unwrap();
        let empty = invocation("/bin/true");
        put(root.path(), "case.test.js", "globalThis.answer = 42;");
        let loaded = seed(root.path(), None, [&node, &empty, &empty]);
        assert!(require_seed(&loaded.capsule.payload.expected).is_err());
        put(root.path(), "case.test.js", "process.exit(7);");
        let loaded = seed(root.path(), None, [&node, &empty, &empty]);
        assert!(require_seed(&loaded.capsule.payload.expected).unwrap_err().to_string().contains("successful Node and Bun"));
        put(root.path(), "case.test.js", "if(process.argv.includes('candidate'))process.kill(process.pid,'SIGTERM');");
        let native = Invocation { after: vec!["candidate".into()], ..node.clone() };
        let loaded = seed(root.path(), None, [&node, &empty, &native]);
        assert!(require_seed(&loaded.capsule.payload.expected).unwrap_err().to_string().contains("non-signal"));
    }

    #[test]
    fn all_three_observations_and_passing_cases_are_part_of_the_predicate() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "case.test.js", "console.log('reference');");
        put(root.path(), "passing.test.js", "globalThis.answer=42;");
        let (node, _) = runtime_invocations(Path::new("/bin/false")).unwrap();
        let empty = invocation("/bin/true");
        let loaded = seed(root.path(), None, [&node, &empty, &empty]);
        let opts = options();
        let oracle = Oracle { runtimes: [&node, &empty, &empty], expected: &loaded.capsule.payload.expected,
            options: &opts, deadline: deadline(), search_deadline: deadline(), statistics: Statistics::default() };
        assert!(oracle.preserves(oracle.expected));
        for mutate in [
            (|r: &mut ProductReport| r.cases[0].bun = None) as fn(&mut ProductReport),
            |r| r.cases[0].bun.as_mut().unwrap().stdout.sha256 = "0".repeat(64),
            |r| r.cases[0].bun.as_mut().unwrap().workspace_delta = None,
            |r| r.cases[0].native.as_mut().unwrap().exit_code = Some(7),
            |r| r.cases[1].node.as_mut().unwrap().stdout.bytes += 1,
            |r| r.cases[0].outcome = CaseOutcome::NativeDivergence,
            |r| { r.cases.pop(); },
            |r| r.filesystem_exclusions.push("**/*".into()),
        ] {
            let mut changed = oracle.expected.clone();
            mutate(&mut changed);
            assert!(!oracle.preserves(&changed));
        }
    }

    #[test]
    fn late_native_drift_prevents_publication_even_when_search_has_no_capacity() {
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let counter = output.path().join("counter");
        fs::write(&counter, "0").unwrap();
        put(root.path(), "case.test.js", &format!(
            "if(process.argv.includes('candidate')){{const fs=require('fs');const p={};const n=Number(fs.readFileSync(p,'utf8'));fs.writeFileSync(p,String(n+1));console.log(n<3?'bad':'drift');}}\n",
            serde_json::to_string(&counter).unwrap()));
        let (node, _) = runtime_invocations(Path::new("/bin/false")).unwrap();
        let empty = invocation("/bin/true");
        let native = Invocation { after: vec!["candidate".into()], ..node.clone() };
        let loaded = seed(root.path(), None, [&node, &empty, &native]);
        let error = minimize_loaded(loaded, [&node, &empty, &native],
            &Options { max_executions: 4, ..options() }, Instant::now()).err().unwrap();
        assert!(error.to_string().contains("final confirmation"), "{error:#}");
        assert_eq!(fs::read_to_string(counter).unwrap(), "4");
        assert_eq!(fs::read_dir(output.path()).unwrap().count(), 1);
    }

    #[test]
    fn missing_second_reference_is_unresolved_not_acceptance_or_a_pair_fallback() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "case.test.js", "console.log('reference');");
        let (node, _) = runtime_invocations(Path::new("/bin/false")).unwrap();
        let empty = invocation("/bin/true");
        let loaded = seed(root.path(), None, [&node, &empty, &empty]);
        let Loaded { capsule, original, candidate } = loaded;
        let inputs = Inputs { original, candidate };
        let missing = Invocation { executable: root.path().join("missing-bun"), before: vec![], after: vec![] };
        let opts = options();
        let mut oracle = Oracle { runtimes: [&node, &missing, &empty], expected: &capsule.payload.expected,
            options: &opts, deadline: deadline(), search_deadline: deadline(), statistics: Statistics::default() };
        assert!(oracle.measure(&inputs, false).unwrap().is_none());
        assert_eq!((oracle.statistics.executions, oracle.statistics.unresolved, oracle.statistics.accepted), (1, 1, 0));
        oracle.runtimes[1] = &empty;
        let final_report = oracle.measure(&inputs, true).unwrap().unwrap();
        assert!(oracle.preserves(&final_report));
        oracle.runtimes[1] = &missing;
        assert!(oracle.measure(&inputs, true).unwrap_err().to_string().contains("final reduction confirmation failed"));
        assert_eq!(inputs.original.digest, capsule.payload.expected.input_sha256);
    }

    #[test]
    fn minified_product_sources_reduce_without_dropping_either_tree_or_reference() {
        let original = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        for (root, value) in [(original.path(), "original"), (candidate.path(), "candidate")] {
            put(root, "case.test.js", &format!("(()=>{{const unused=12345;require('fs').writeFileSync('artifact','{value}');console.log('measured');}})();"));
            put(root, "passing.test.js", "globalThis.answer=42;");
        }
        let (node, _) = runtime_invocations(Path::new("/bin/false")).unwrap();
        let empty = invocation("/bin/true");
        let loaded = seed(original.path(), Some(candidate.path()), [&node, &empty, &node]);
        let expected = loaded.capsule.payload.expected.cases.clone();
        let reduced = minimize_loaded(loaded, [&node, &empty, &node], &options(), Instant::now()).unwrap();
        assert_eq!(reduced.report.verdict, "REDUCED");
        assert_eq!(reduced.report.validation.cases, expected);
        assert_eq!(reduced.report.validation.passed, 1);
        assert!(reduced.report.statistics.syntax.accepted >= 2);
        assert!(reduced.report.statistics.executions <= options().max_executions);
        let path = output.path().join("syntax-product.json");
        let pin = reduced.write_capsule(&path).unwrap().content_sha256;
        let exported = export_inputs(&path, &pin, &output.path().join("export")).unwrap();
        for tree in ["original", "candidate"] {
            let text = fs::read_to_string(exported.destination.join(tree).join("case.test.js")).unwrap();
            assert!(!text.contains("unused"), "{text}");
            assert!(!exported.destination.join(tree).join("artifact").exists());
        }
        let loaded = load(&path, Some(&pin), deadline()).unwrap();
        let repeated = reexecute(loaded, [&node, &empty, &node], false, deadline()).unwrap();
        assert_eq!(repeated.verdict, "REPRODUCED");
        assert_eq!(repeated.validation.cases, expected);
        assert!(!original.path().join("artifact").exists());
        assert!(!candidate.path().join("artifact").exists());
    }
}
