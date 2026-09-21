//! Native, non-executing package graph inspection and operator-supplied pin checks.
#![forbid(unsafe_code)]

use franken_module_graph_schema as schema_versions;
#[allow(dead_code)]
#[path = "../../crates/franken-node/src/supply_chain/module_resolution_graph.rs"]
mod module_resolution_graph;

use clap::Parser;
use module_resolution_graph::{build_canonical_module_resolution_graph, recompute_module_resolution_graph_hash};
use serde_json::{Value, json};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Inspect importer-specific npm lockfile pins without running project code.
/// This is metadata evidence, not proof of installation, trust, or runtime parity.
#[derive(Parser)]
#[command(version)]
struct Args {
    project: PathBuf,
    /// Inspect declared edges for this dependency instead of exporting the whole graph.
    #[arg(long)]
    dependency: Option<String>,
    /// Exact project-relative manifest path; defaults to package.json.
    #[arg(long, requires = "dependency")]
    importer: Option<String>,
    /// Require equality with an independently trusted sha256:<hex> graph hash.
    #[arg(long)]
    expected_hash: Option<String>,
    /// Exit nonzero if any selected edge has neither a lockfile pin nor workspace intent.
    #[arg(long)]
    require_resolved: bool,
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
    let graph = build_canonical_module_resolution_graph(&args.project)?;
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

fn main() -> ExitCode {
    let (report, code) = match inspect(Args::parse()) {
        Ok(result) => result,
        Err(error) => (json!({"schema_version": "franken-node/module-graph-inspection/v1",
            "scope": "lockfile-metadata-only", "execution_performed": false,
            "release_certification": false, "verdict": "ERROR", "error": error.to_string()}), 2),
    };
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer_pretty(&mut stdout, &report).is_err()
        || stdout.write_all(b"\n").and_then(|()| stdout.flush()).is_err()
    {
        return ExitCode::from(2);
    }
    ExitCode::from(code)
}
