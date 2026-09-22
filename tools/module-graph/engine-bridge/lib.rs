//! Compile the exact product bridge against the actual sibling engine crate.
#![forbid(unsafe_code)]

use franken_module_graph_schema as schema_versions;
#[path = "../../../crates/franken-node/src/supply_chain/module_resolution_graph.rs"]
pub mod module_resolution_graph;

use std::io::{self, Read};
use std::path::Path;

// Same focused-host bounded read as the module-graph command. All resolution,
// capsule reconstruction, registry admission and engine adapter code is loaded
// unmodified from the product modules; no engine contracts are mocked.
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