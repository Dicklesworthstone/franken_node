//! Compile the production dependency gate and its shared graph selector together.
#![forbid(unsafe_code)]

use franken_dependency_admission_schema as schema_versions;

#[path = "../../crates/franken-node/src/migration/dependency_admission.rs"]
pub mod dependency_admission;

#[path = "../../crates/franken-node/src/supply_chain/module_resolution_graph.rs"]
pub mod module_resolution_graph;

// Preserve the product namespaces used by the mutually shared graph/admission
// modules, including their existing integration tests. No selector is mocked.
pub mod migration {
    pub use crate::dependency_admission;
}

pub mod supply_chain {
    pub use crate::module_resolution_graph;
}
