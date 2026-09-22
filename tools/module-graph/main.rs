//! Native, non-executing package graph inspection and operator-supplied pin checks.
#![forbid(unsafe_code)]

use franken_module_graph_schema as schema_versions;
#[allow(dead_code)]
#[path = "../../crates/franken-node/src/supply_chain/module_resolution_graph.rs"]
mod module_resolution_graph;

use module_resolution_graph::package_targets as package_target_resolution;

use clap::Parser;
use module_resolution_graph::{build_canonical_module_resolution_graph, recompute_module_resolution_graph_hash};
use module_resolution_graph::dependency_topology;
use serde_json::{Value, json};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Inspect importer-specific npm lockfile pins without running project code.
/// This is metadata evidence, not proof of installation, trust, or runtime parity.
#[derive(Parser)]
#[command(version)]
struct Args {
    #[arg(required_unless_present = "replay_source_capsule", conflicts_with = "replay_source_capsule")]
    project: Option<PathBuf>,
    /// Inspect declared edges for this dependency instead of exporting the whole graph.
    #[arg(long, group = "importer_query")]
    dependency: Option<String>,
    /// Traverse all declared transitive requirements from the selected importer.
    #[arg(long, group = "importer_query")]
    transitive: bool,
    /// Find known dependents of one exact locked/workspace package location.
    #[arg(long, conflicts_with_all = ["importer_query", "importer"])]
    impact: Option<String>,
    /// Exact project-relative manifest path; defaults to package.json.
    #[arg(long, requires = "importer_query")]
    importer: Option<String>,
    /// Require an independently trusted sha256:<hex> hash for this query scope.
    #[arg(long)]
    expected_hash: Option<String>,
    /// Require resolved edges. Transitive queries also reject incomplete kind metadata or workspace intent.
    #[arg(long)]
    require_resolved: bool,
    /// Select a package's export target for . or an exact ./ subpath.
    #[arg(long, groups = ["target_query", "condition_query"], conflicts_with_all = ["importer_query", "impact", "importer", "require_resolved"])]
    resolve_export: Option<String>,
    /// Select an internal # import target from a package manifest.
    #[arg(long, groups = ["target_query", "condition_query"], conflicts_with_all = ["importer_query", "impact", "importer", "require_resolved"])]
    resolve_import: Option<String>,
    /// Exact project-relative package.json to inspect; default: package.json.
    #[arg(long, requires = "target_query")]
    package_manifest: Option<String>,
    /// Complete active condition set, repeatable. Default: node plus import/require mode.
    #[arg(long = "condition", requires = "condition_query")]
    conditions: Vec<String>,
    /// Resolve a module request to an existing captured file without executing it.
    #[arg(long, groups = ["condition_query", "file_query"], requires = "from", conflicts_with_all = ["importer_query", "impact", "importer", "require_resolved", "target_query", "package_manifest"])]
    resolve_module: Option<String>,
    /// Capture static and literal dependency sources reachable from this entrypoint.
    #[arg(long, groups = ["condition_query", "file_query"], conflicts_with_all = ["importer_query", "impact", "importer", "require_resolved", "target_query", "package_manifest", "from", "resolution_mode"])]
    capture_source_graph: Option<String>,
    /// Persist captured source/manifest bytes and lookup observations privately to a NEW file.
    #[arg(long, requires = "capture_source_graph")]
    write_source_capsule: Option<PathBuf>,
    /// Recompute source-graph analysis from a pinned capsule without an original project.
    #[arg(long, requires = "expected_hash", conflicts_with_all = ["project", "importer_query", "impact", "importer", "require_resolved", "target_query", "package_manifest", "file_query", "from", "resolution_mode", "conditions", "allow_contained_symlinks", "write_source_capsule"])]
    replay_source_capsule: Option<PathBuf>,
    /// Existing canonical project-relative importing file for --resolve-module.
    #[arg(long, requires = "resolve_module")]
    from: Option<String>,
    /// Resolution algorithm; defaults to import. Does not execute either runtime.
    #[arg(long, requires = "resolve_module", value_parser = ["import", "require"])]
    resolution_mode: Option<String>,
    /// Follow bounded relative symlinks only while every component stays inside the project.
    #[arg(long, requires = "file_query")]
    allow_contained_symlinks: bool,
}

impl Args {
    fn project(&self) -> Result<&Path, &'static str> {
        self.project.as_deref().ok_or("live inspection requires a project path")
    }
}

// The standalone host supplies the same bounded-read interface used by the
// primary crate. All parsing, graph construction and hashing is production code.
pub fn bounded_read_to_string(path: &Path, limit: u64) -> io::Result<String> {
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "metadata is nonregular or exceeds its byte limit"));
    }
    let mut text = String::new();
    file.take(limit.saturating_add(1)).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "metadata exceeds its byte limit"));
    }
    Ok(text)
}

fn inspect(args: Args) -> Result<(Value, u8), Box<dyn std::error::Error>> {
    if let Some(expected) = &args.expected_hash {
        let digest = expected.strip_prefix("sha256:").ok_or("expected hash must start with sha256:")?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) {
            return Err("expected hash requires exactly 64 lowercase hexadecimal digits".into());
        }
    }
    if args.replay_source_capsule.is_some() { return inspect_capsule_replay(&args); }
    if args.capture_source_graph.is_some() { return inspect_source_graph(&args); }
    if args.resolve_module.is_some() { return inspect_module_file(&args); }
    if args.resolve_export.is_some() || args.resolve_import.is_some() { return inspect_targets(&args); }
    if args.transitive || args.impact.is_some() { return inspect_topology(&args); }
    let graph = build_canonical_module_resolution_graph(args.project()?)?;
    if graph.canonical_hash != recompute_module_resolution_graph_hash(&graph)? {
        return Err("internal graph hash disagreement".into());
    }
    let selected: Vec<_> = if let Some(dependency) = &args.dependency {
        let path = args.importer.as_deref().unwrap_or("package.json");
        let importer = graph.packages.iter().find(|package| package.relative_manifest_path == path)
            .ok_or("importer is not an exact captured manifest path")?;
        let edges: Vec<_> = graph.dependency_edges.iter().filter(|edge|
            edge.from_package_id == importer.package_id && edge.dependency_name == *dependency).collect();
        if edges.is_empty() { return Err("dependency is not declared by the selected importer".into()); }
        edges
    } else {
        graph.dependency_edges.iter().collect()
    };
    let unresolved = selected.iter().filter(|edge|
        edge.lockfile_package_path.is_none() && edge.target_package_id.is_none()).count();
    let matched = args.expected_hash.as_ref().map(|expected| *expected == graph.canonical_hash);
    let verdict = if matched == Some(false) { "HASH_MISMATCH" }
        else if args.require_resolved && unresolved > 0 { "UNRESOLVED" }
        else { "INSPECTED" };
    let mut report = json!({
        "schema_version": "franken-node/module-graph-inspection/v1",
        "scope": "lockfile-metadata-only",
        "execution_performed": false,
        "release_certification": false,
        "verdict": verdict,
        "canonical_hash": graph.canonical_hash,
        "expected_hash_matched": matched,
        "selected_edges": selected.len(),
        "unresolved_edges": unresolved,
    });
    if args.dependency.is_some() {
        report["edges"] = serde_json::to_value(&selected)?;
        report["pins"] = serde_json::to_value(graph.lockfile_pins.iter().filter(|pin|
            selected.iter().any(|edge| edge.lockfile_package_path.as_deref() == Some(pin.package_path.as_str())))
            .collect::<Vec<_>>())?;
    } else {
        report["graph"] = serde_json::to_value(&graph)?;
    }
    Ok((report, if verdict == "INSPECTED" { 0 } else { 1 }))
}

fn inspect_topology(args: &Args) -> Result<(Value, u8), Box<dyn std::error::Error>> {
    let topology = dependency_topology::build(args.project()?)?;
    let (query, result, fully_resolved, unresolved, selected_edges) = if let Some(target) = &args.impact {
        let result = topology.impact(target)?;
        ("impact", serde_json::to_value(&result)?, result.fully_resolved,
            result.unresolved_edges.len(), topology.edges().len())
    } else {
        let manifest = args.importer.as_deref().unwrap_or("package.json");
        let importer = topology.nodes().iter().find(|node| node.manifest_path == manifest)
            .ok_or("importer is not an exact captured manifest or locked package manifest path")?;
        let result = topology.closure(&importer.location)?;
        let reachable: std::collections::BTreeSet<_> = result.reachable.iter().collect();
        let selected = topology.edges().iter().filter(|edge| reachable.contains(&edge.importer)).count();
        ("closure", serde_json::to_value(&result)?, result.fully_resolved, result.unresolved_edges.len(), selected)
    };
    let matched = args.expected_hash.as_ref().map(|expected| expected == topology.canonical_hash());
    let verdict = if matched == Some(false) { "HASH_MISMATCH" }
        else if args.require_resolved && !fully_resolved { "UNRESOLVED" } else { "INSPECTED" };
    let mut report = json!({
        "schema_version": "franken-node/module-graph-inspection/v1",
        "scope": "declared-dependency-topology", "query": query,
        "execution_performed": false, "release_certification": false,
        "verdict": verdict, "canonical_hash": topology.canonical_hash(),
        "expected_hash_matched": matched, "fully_resolved": fully_resolved,
        "selected_edges": selected_edges, "unresolved_edges": unresolved,
        "topology": topology,
    });
    report[query] = result;
    Ok((report, if verdict == "INSPECTED" { 0 } else { 1 }))
}

#[cfg(unix)]
fn inspect_source_graph(args: &Args) -> Result<(Value, u8), Box<dyn std::error::Error>> {
    use module_resolution_graph::file_resolution::{SymlinkPolicy, source_graph};
    let entrypoint = args.capture_source_graph.as_deref().ok_or("missing source graph entrypoint")?;
    let options = source_graph::GraphOptions {
        symlink_policy: if args.allow_contained_symlinks { SymlinkPolicy::Contained } else { SymlinkPolicy::Reject },
        conditions: if args.conditions.is_empty() { None } else { Some(args.conditions.clone()) },
    };
    let mut report = json!({"schema_version":"franken-node/module-graph-inspection/v1",
        "scope":"static-and-literal-module-requests", "execution_performed":false,
        "release_certification":false, "runtime_completeness":false, "source_graph":null});
    match source_graph::capture(args.project()?, entrypoint, options) {
        Ok(captured) => {
            let graph = captured.report();
            let matched = args.expected_hash.as_ref().map(|pin| pin == &graph.input_hash);
            report["input_hash"] = json!(graph.input_hash);
            report["expected_hash_matched"] = json!(matched);
            if matched == Some(false) {
                report["verdict"] = json!("HASH_MISMATCH");
                return Ok((report, 1));
            }
            if let Some(path) = &args.write_source_capsule {
                let capsule = source_graph::capsule::encode(&captured)?;
                publish_capsule(path, capsule.bytes())?;
                report["capsule_path"] = json!(path);
                report["capsule_hash"] = json!(capsule.digest());
                report["capsule_bytes"] = json!(capsule.bytes().len());
            }
            report["verdict"] = json!(if graph.fully_resolved { "CAPTURED" } else { "INCOMPLETE" });
            report["source_graph"] = serde_json::to_value(graph)?;
            Ok((report, if graph.fully_resolved { 0 } else { 1 }))
        }
        Err(error) => {
            let missing = matches!(error.code, "ERR_MODULE_NOT_FOUND" | "MODULE_NOT_FOUND");
            report["verdict"] = json!(if missing { "UNRESOLVED" } else { "ERROR" });
            report["error_code"] = json!(error.code);
            report["error"] = json!(error.detail);
            Ok((report, if missing { 1 } else { 2 }))
        }
    }
}

#[cfg(not(unix))]
fn inspect_source_graph(_: &Args) -> Result<(Value, u8), Box<dyn std::error::Error>> {
    Err("source graph capture requires Unix descriptor-relative capture".into())
}

/// Stage complete private bytes before no-clobber publication. A saved capsule
/// is not evidence of successful analysis; incomplete graphs are retained too.
#[cfg(unix)]
fn publish_capsule(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    // This operator-supplied directory is trusted, not part of the guest tree.
    // A same-directory staging file avoids cross-filesystem publication.
    let directory = std::fs::File::open(parent)?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.as_file().set_permissions(std::fs::Permissions::from_mode(0o600))?;
    staged.write_all(bytes)?;
    staged.flush()?;
    staged.as_file().sync_all()?;
    staged.persist_noclobber(path).map_err(|e| e.error)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn read_capsule(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use module_resolution_graph::file_resolution::source_graph::capsule::MAX_CAPSULE_BYTES;
    use rustix::fs::{Mode, OFlags, open};
    use std::fs::{File, Metadata};
    use std::os::unix::fs::MetadataExt;
    // Do not hang on a FIFO or follow a substituted final symlink. The
    // operator selects the containing directory; payload paths are never opened.
    let file = File::from(open(path, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?);
    let before = file.metadata()?;
    if !before.is_file() || before.len() > MAX_CAPSULE_BYTES as u64 {
        return Err("source capsule must be a bounded regular file".into());
    }
    let identity = |m: &Metadata| (m.dev(), m.ino(), m.len(), m.mode(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec());
    let mut bytes = Vec::new();
    (&file).take(MAX_CAPSULE_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CAPSULE_BYTES || bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata()?) {
        return Err("source capsule changed or exceeded its byte limit during capture".into());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn inspect_capsule_replay(args: &Args) -> Result<(Value, u8), Box<dyn std::error::Error>> {
    use module_resolution_graph::file_resolution::source_graph::capsule;
    let path = args.replay_source_capsule.as_deref().ok_or("missing source capsule")?;
    let pin = args.expected_hash.as_deref().ok_or("replay requires an independently obtained capsule hash")?;
    let bytes = read_capsule(path)?;
    let mut report = json!({"schema_version":"franken-node/module-graph-inspection/v1",
        "scope":"captured-source-graph-replay", "execution_performed":false,
        "release_certification":false, "runtime_completeness":false,
        "filesystem_verified":false, "replay_verified":false, "source_graph":null});
    match capsule::replay(&bytes, pin) {
        Ok(captured) => {
            let graph = captured.report();
            report["verdict"] = json!(if graph.fully_resolved { "REPLAYED" } else { "INCOMPLETE" });
            report["capsule_hash"] = json!(pin);
            report["capsule_bytes"] = json!(bytes.len());
            report["expected_hash_matched"] = json!(true);
            report["input_hash"] = json!(graph.input_hash);
            report["replay_verified"] = json!(true);
            report["source_graph"] = serde_json::to_value(graph)?;
            Ok((report, if graph.fully_resolved { 0 } else { 1 }))
        }
        Err(error) => {
            let mismatch = error.code == "ERR_MODULE_CAPSULE_PIN_MISMATCH";
            report["verdict"] = json!(if mismatch { "HASH_MISMATCH" } else { "ERROR" });
            if mismatch { report["expected_hash_matched"] = json!(false); }
            report["error_code"] = json!(error.code);
            report["error"] = json!(error.detail);
            Ok((report, if mismatch { 1 } else { 2 }))
        }
    }
}

#[cfg(not(unix))]
fn inspect_capsule_replay(_: &Args) -> Result<(Value, u8), Box<dyn std::error::Error>> {
    Err("this build exposes source-graph analysis and capsule replay only on Unix".into())
}

#[cfg(unix)]
fn inspect_module_file(args: &Args) -> Result<(Value, u8), Box<dyn std::error::Error>> {
    use module_resolution_graph::file_resolution::{self, ResolutionMode, SymlinkPolicy};
    let mode = match args.resolution_mode.as_deref().unwrap_or("import") {
        "import" => ResolutionMode::Import, "require" => ResolutionMode::Require,
        _ => return Err("invalid module resolution mode".into()),
    };
    let conditions = if args.conditions.is_empty() { mode.default_conditions() } else { args.conditions.clone() };
    let importer = args.from.as_deref().ok_or("module resolution requires --from")?;
    let request = args.resolve_module.as_deref().ok_or("missing module request")?;
    let symlink_policy = if args.allow_contained_symlinks { SymlinkPolicy::Contained } else { SymlinkPolicy::Reject };
    let mut report = json!({"schema_version":"franken-node/module-graph-inspection/v1",
        "scope":"project-contained-module-resolution", "execution_performed":false,
        "release_certification":false, "filesystem_verified":false, "resolution":null,
        "symlink_policy":symlink_policy});
    match file_resolution::resolve_with_policy(args.project()?, importer, request, mode, &conditions, symlink_policy) {
        Ok(captured) => {
            let matched = args.expected_hash.as_ref().map(|pin| pin == &captured.report.input_hash);
            report["input_hash"] = json!(captured.report.input_hash);
            report["expected_hash_matched"] = json!(matched);
            if matched == Some(false) {
                report["verdict"] = json!("HASH_MISMATCH");
                return Ok((report, 1));
            }
            report["verdict"] = json!("RESOLVED");
            report["filesystem_verified"] = json!(true);
            report["resolution"] = serde_json::to_value(&captured.report)?;
            // The captured source is intentionally never serialized to stdout.
            Ok((report, 0))
        }
        Err(error) => {
            let missing = matches!(error.code, "ERR_MODULE_NOT_FOUND" | "MODULE_NOT_FOUND"
                | "ERR_UNSUPPORTED_DIR_IMPORT" | "ERR_PACKAGE_MAP_ABSENT"
                | "ERR_PACKAGE_PATH_NOT_EXPORTED" | "ERR_PACKAGE_IMPORT_NOT_DEFINED");
            let builtin = error.code == "ERR_RUNTIME_MODULE_REQUIRED";
            report["verdict"] = json!(if builtin { "RUNTIME_REQUIRED" } else if missing { "UNRESOLVED" } else { "ERROR" });
            report["error_code"] = json!(error.code);
            report["error"] = json!(error.detail);
            Ok((report, if missing || builtin { 1 } else { 2 }))
        }
    }
}

#[cfg(not(unix))]
fn inspect_module_file(_: &Args) -> Result<(Value, u8), Box<dyn std::error::Error>> {
    Err("module file resolution requires Unix descriptor-relative capture".into())
}

fn inspect_targets(args: &Args) -> Result<(Value, u8), Box<dyn std::error::Error>> {
    use package_target_resolution::{MapKind, PackageMap};
    let manifest = args.package_manifest.as_deref().unwrap_or("package.json");
    let source = capture_manifest(args.project()?, manifest)?;
    let maps = PackageMap::parse(&source)?;
    let (kind, request) = match (&args.resolve_export, &args.resolve_import) {
        (Some(request), None) => (MapKind::Exports, request),
        (None, Some(request)) => (MapKind::Imports, request),
        _ => return Err("select exactly one package-map query".into()),
    };
    let conditions = if args.conditions.is_empty() { vec!["node".into(), "import".into()] }
        else { args.conditions.clone() };
    let matched = args.expected_hash.as_ref().map(|pin| pin == maps.input_hash());
    let mut report = json!({
        "schema_version": "franken-node/module-graph-inspection/v1",
        "scope": "package-map-target-selection", "query": kind, "request": request,
        "manifest": manifest, "input_hash": maps.input_hash(), "conditions": conditions,
        "expected_hash_matched": matched, "execution_performed": false,
        "release_certification": false, "filesystem_verified": false, "selection": null,
    });
    // Do not select from changed metadata under an independently reviewed pin.
    if matched == Some(false) {
        report["verdict"] = json!("HASH_MISMATCH");
        return Ok((report, 1));
    }
    match maps.select(kind, request, &conditions) {
        Ok(selection) => {
            report["verdict"] = json!("SELECTED");
            report["selection"] = serde_json::to_value(selection)?;
            Ok((report, 0))
        }
        Err(error) => {
            let missing = matches!(error.code, "ERR_PACKAGE_MAP_ABSENT"
                | "ERR_PACKAGE_PATH_NOT_EXPORTED" | "ERR_PACKAGE_IMPORT_NOT_DEFINED");
            report["verdict"] = json!(if missing { "UNRESOLVED" } else { "ERROR" });
            report["error_code"] = json!(error.code);
            report["error"] = json!(error.detail);
            Ok((report, if missing { 1 } else { 2 }))
        }
    }
}

/// Anchor every path component to an opened directory, never a symlink-following
/// joined path. Nonblocking final open rejects FIFOs/devices without hanging.
/// The opened regular file, not a later reread by pathname, supplies the pin and
/// ordered maps. This is bounded metadata capture, not a filesystem sandbox.
#[cfg(unix)]
fn capture_manifest(project: &Path, name: &str) -> Result<String, Box<dyn std::error::Error>> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::fs::{File, Metadata};
    use std::os::unix::fs::MetadataExt;

    let parts: Vec<_> = name.split('/').collect();
    if name.len() > 4096 || parts.len() > 64 || name.contains(['\\', ':'])
        || name.chars().any(char::is_control)
        || parts.iter().any(|p| p.is_empty() || matches!(*p, "." | ".." | ".git" | ".beads"))
        || parts.last() != Some(&"package.json") {
        return Err("package manifest must be a canonical project-relative package.json path".into());
    }
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(open(project, directory_flags, Mode::empty())?);
    for component in &parts[..parts.len() - 1] {
        directory = File::from(openat(&directory, *component, directory_flags, Mode::empty())?);
    }
    let file = File::from(openat(&directory, "package.json",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?);
    let before = file.metadata()?;
    let limit = package_target_resolution::MAX_MANIFEST_BYTES as u64;
    if !before.is_file() || before.len() > limit {
        return Err("package manifest must be an ordinary file no larger than 512 KiB".into());
    }
    let identity = |m: &Metadata| (m.dev(), m.ino(), m.size(), m.mode(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec());
    let mut text = String::new();
    (&file).take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit || text.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata()?) {
        return Err("package manifest changed or exceeded its byte limit during capture".into());
    }
    Ok(text)
}

#[cfg(not(unix))]
fn capture_manifest(_: &Path, _: &str) -> Result<String, Box<dyn std::error::Error>> {
    Err("package-map file capture requires Unix descriptor-relative no-follow opening".into())
}

fn main() -> ExitCode {
    let args = Args::parse();
    let scope = if args.replay_source_capsule.is_some() { "captured-source-graph-replay" }
        else if args.capture_source_graph.is_some() { "static-and-literal-module-requests" }
        else if args.resolve_module.is_some() { "project-contained-module-resolution" }
        else if args.resolve_export.is_some() || args.resolve_import.is_some() { "package-map-target-selection" }
        else if args.transitive || args.impact.is_some() { "declared-dependency-topology" }
        else { "lockfile-metadata-only" };
    let (report, code) = match inspect(args) {
        Ok(result) => result,
        Err(error) => (json!({"schema_version": "franken-node/module-graph-inspection/v1",
            "scope": scope, "execution_performed": false,
            "replay_verified": false, "runtime_completeness": false,
            "release_certification": false, "verdict": "ERROR", "error": error.to_string(),
            "error_code": error.downcast_ref::<package_target_resolution::ResolutionError>().map(|e| e.code)}), 2),
    };
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer_pretty(&mut stdout, &report).is_err()
        || stdout.write_all(b"\n").and_then(|()| stdout.flush()).is_err()
    {
        return ExitCode::from(2);
    }
    ExitCode::from(code)
}
