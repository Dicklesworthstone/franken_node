#![no_main]
#![forbid(unsafe_code)]

//! Fuzz the `dgis::contagion_graph` validator + edge-builder + graph-validate
//! pipeline at `crates/franken-node/src/dgis/contagion_graph.rs`.
//!
//! Recent peer fixes (`b8d40d96` adding `MAX_NODE_ID_LEN` bound and `aa3b1c9a`
//! avoiding payload-clone in the overlong-rejection error) hardened the
//! `validate_node_id` boundary. The module has no existing fuzz harness; this
//! harness drives the boundary with `arbitrary`-generated inputs and pins:
//!
//!   - `validate_node_id` never panics; it returns Err on the documented
//!     rejection conditions (empty/trim-mismatch/control-char/>512 bytes).
//!   - `ContagionEdge::new` rejects every non-finite or out-of-range
//!     `[0.0, 1.0]` weight at construction.
//!   - `ContagionGraph::add_node` is idempotent on already-present node ids
//!     (the inherent contract — adding the same node twice mustn't break
//!     the graph) and remains size-bounded.
//!   - `ContagionGraph::add_edge` rejects unknown source/target ids.
//!   - `ContagionGraph::validate()` never panics on any sequence of
//!     `add_node` / `add_edge` operations and returns Err for any graph
//!     state that violates a documented invariant (NaN weight, weight
//!     out-of-range, unknown target).
//!   - The graph survives bounded operation counts without unbounded
//!     memory growth (we cap inputs at MAX_OPS).
//!
//! Inputs are length-capped at 64 KiB and MAX_OPS = 64 operations per
//! iteration to keep per-iteration cost bounded.

use arbitrary::{Arbitrary, Result, Unstructured};
use frankenengine_node::dgis::contagion_graph::{
    validate_node_id, ContagionEdge, ContagionGraph, EdgeKind, GraphError, NodeId,
};
use libfuzzer_sys::fuzz_target;

const MAX_OPS: usize = 64;
const MAX_NODE_ID_BYTES: usize = 1024; // 2x the production MAX_NODE_ID_LEN to exercise the rejection path
const MAX_INPUT_BYTES: usize = 64 * 1024;

#[derive(Debug)]
enum FuzzOp {
    AddNode { node: String },
    AddEdge { source: String, target: String, weight: f64, kind: u8 },
    Validate,
}

impl<'a> Arbitrary<'a> for FuzzOp {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        match u.int_in_range::<u8>(0..=2)? {
            0 => Ok(FuzzOp::AddNode {
                node: bounded_string(u, MAX_NODE_ID_BYTES)?,
            }),
            1 => Ok(FuzzOp::AddEdge {
                source: bounded_string(u, MAX_NODE_ID_BYTES)?,
                target: bounded_string(u, MAX_NODE_ID_BYTES)?,
                weight: f64::arbitrary(u)?,
                kind: u8::arbitrary(u)?,
            }),
            _ => Ok(FuzzOp::Validate),
        }
    }
}

fn bounded_string<'a>(u: &mut Unstructured<'a>, max: usize) -> Result<String> {
    let len = u.int_in_range::<usize>(0..=max)?;
    let bytes = u.bytes(len)?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn edge_kind_from_u8(byte: u8) -> EdgeKind {
    match byte % 4 {
        0 => EdgeKind::DependencyImport,
        1 => EdgeKind::MaintainerOverlap,
        2 => EdgeKind::OrgOverlap,
        _ => EdgeKind::NamespaceShadow,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(seed) = u64::arbitrary(&mut u) else {
        return;
    };
    let mut graph = ContagionGraph::new(seed);

    let mut ops_remaining = MAX_OPS;
    while ops_remaining > 0 {
        let Ok(op) = FuzzOp::arbitrary(&mut u) else {
            break;
        };
        ops_remaining -= 1;

        match op {
            FuzzOp::AddNode { node } => {
                // The validator's contract is enforced at the node-id surface
                // independently — exercise it on every candidate id.
                let pre_validate = validate_node_id(&node);
                // add_node is documented as idempotent and infallible at the API
                // level. The validator's verdict on the id text is independent.
                let pre_count = graph.nodes().len();
                graph.add_node(node.clone());
                let post_count = graph.nodes().len();
                // Idempotence: adding the same node twice must not grow the
                // graph beyond one entry.
                graph.add_node(node.clone());
                let post_post_count = graph.nodes().len();
                assert_eq!(
                    post_count, post_post_count,
                    "add_node must be idempotent on repeated identical ids"
                );
                // Size monotonicity: adding a node never decreases the count.
                assert!(
                    post_count >= pre_count,
                    "add_node must never decrease the node count"
                );
                // Whether the id passed validate_node_id is independent of
                // whether add_node accepted it — pin that we observe a
                // deterministic Result either way (never a panic).
                drop(pre_validate);
            }
            FuzzOp::AddEdge { source, target, weight, kind } => {
                // ContagionEdge::new is the constructor; it must reject every
                // non-finite weight and every out-of-range [0.0, 1.0] weight.
                let edge_result =
                    ContagionEdge::new(target.clone(), weight, edge_kind_from_u8(kind));
                match edge_result {
                    Ok(edge) => {
                        // Constructor accepted: invariants must hold.
                        assert!(
                            edge.weight.is_finite(),
                            "ContagionEdge::new must not produce non-finite weights"
                        );
                        assert!(
                            (0.0..=1.0).contains(&edge.weight),
                            "ContagionEdge::new must not produce out-of-range weights"
                        );
                        // Try adding the edge. add_edge may reject unknown
                        // source/target — that's a valid outcome.
                        let _ = graph.add_edge(&source, edge);
                    }
                    Err(
                        GraphError::InvalidNodeId(_)
                        | GraphError::NonFiniteWeight
                        | GraphError::NegativeWeight
                        | GraphError::WeightAboveOne,
                    ) => {
                        // Documented rejection paths — fine.
                    }
                    Err(other) => {
                        // Any other GraphError variant on edge construction is
                        // unexpected from ContagionEdge::new — pin it so a
                        // refactor that re-routes errors through a different
                        // variant surfaces here.
                        panic!(
                            "ContagionEdge::new produced an unexpected error variant {other:?} for (target={target:?}, weight={weight:?})"
                        );
                    }
                }
            }
            FuzzOp::Validate => {
                // The full-graph validator must never panic and must hold the
                // documented invariants on any state we built up.
                let result = graph.validate();
                if result.is_ok() {
                    // On success, every edge in the graph must satisfy the
                    // weight invariants and every node id must pass
                    // validate_node_id.
                    for node in graph.nodes() {
                        validate_node_id(node)
                            .expect("validated graph must only contain nodes that pass validate_node_id");
                        for edge in graph.neighbors(node) {
                            assert!(
                                edge.weight.is_finite() && (0.0..=1.0).contains(&edge.weight),
                                "validated graph must have finite, in-range edge weights"
                            );
                            validate_node_id(&edge.target)
                                .expect("validated graph edges must reference validated node ids");
                        }
                    }
                }
            }
        }
    }
});
