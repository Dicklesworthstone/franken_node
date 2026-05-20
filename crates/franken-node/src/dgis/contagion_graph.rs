//! Contagion graph foundation for the DGIS adversarial contagion simulator.
//!
//! Sub-task 1 of bd-1q38.1: defines the `ContagionGraph` + `ContagionEdge`
//! types used by the later simulator step function (sub-task 2) and the
//! adversarial campaign profiles (sub-task 3).
//!
//! Design constraints (per bd-1q38 acceptance criteria):
//!
//! * Deterministic topology generation: identical `seed` + parameters
//!   produces a byte-identical graph (key invariant for fixed-seed
//!   reproducibility of the eventual simulator).
//! * No external RNG dependency — uses an inline SplitMix64 stream so
//!   the type compiles without adding new crates.
//! * All `f64` edge weights are `is_finite()`-guarded; non-finite weights
//!   are rejected at construction time *and* by `validate()` so a corrupted
//!   graph from elsewhere cannot poison downstream consumers.
//! * Counters use `saturating_add` per the project's hardening conventions
//!   to avoid overflow-based bypass in long-running batch sweeps.
//!
//! Future sub-tasks layered on top of this file:
//!
//! 2. step function in `contagion_simulator.rs`
//! 3. campaign profile fixtures under `tests/security/contagion_profiles/`
//! 4. integration test in `tests/security/dgis_contagion_simulator.rs`
//! 5. verification gate script + evidence JSON

use std::collections::{BTreeMap, BTreeSet};

/// Stable, human-readable identifier for a node in the dependency graph.
///
/// Using `String` (rather than a numeric id) keeps the simulator output
/// directly auditable against package names and matches the format the
/// later JSON campaign profiles will use.
pub type NodeId = String;

/// Validate a node id before it enters the graph.
///
/// Node ids are surfaced in fixture paths, reports, and operator output.
/// Rejecting control characters at the graph boundary prevents downstream path
/// and display layers from seeing split identifiers or injected output lines.
pub fn validate_node_id(node: &NodeId) -> Result<(), GraphError> {
    let trimmed = node.trim();
    if trimmed.is_empty() || node != trimmed || node.chars().any(char::is_control) {
        return Err(GraphError::InvalidNodeId(node.clone()));
    }
    Ok(())
}

/// Kind of relationship represented by an edge.
///
/// The four variants line up with the supply-chain compromise vectors that
/// the simulator must reason about per bd-1q38:
/// * `DependencyImport`  — A depends on B (xz-style transitive propagation)
/// * `MaintainerOverlap` — same maintainer in commit access for A and B
///   (xz-style social-engineering pivot)
/// * `OrgOverlap`        — same publishing org (dependency-confusion pivot)
/// * `NamespaceShadow`   — typosquat / shadow namespace relationship
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    DependencyImport,
    MaintainerOverlap,
    OrgOverlap,
    NamespaceShadow,
}

/// Directed edge in the contagion graph.
///
/// `weight` is a propagation-probability-like scalar in `[0.0, 1.0]`. It is
/// validated at construction so downstream code can treat it as a finite,
/// non-negative number without re-checking.
#[derive(Debug, Clone, PartialEq)]
pub struct ContagionEdge {
    pub target: NodeId,
    pub weight: f64,
    pub edge_kind: EdgeKind,
}

impl ContagionEdge {
    /// Construct a new edge, rejecting any non-finite or negative weight.
    ///
    /// Per project conventions, every `f64` is `is_finite()`-guarded before
    /// it can enter the system.
    pub fn new(target: NodeId, weight: f64, edge_kind: EdgeKind) -> Result<Self, GraphError> {
        validate_node_id(&target)?;
        if !weight.is_finite() {
            return Err(GraphError::NonFiniteWeight);
        }
        if weight < 0.0 {
            return Err(GraphError::NegativeWeight);
        }
        if weight > 1.0 {
            return Err(GraphError::WeightAboveOne);
        }
        Ok(Self {
            target,
            weight,
            edge_kind,
        })
    }
}

/// Errors that the contagion graph can produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    /// A weight was NaN or +/- infinity.
    NonFiniteWeight,
    /// A weight was negative; propagation probabilities must be >= 0.
    NegativeWeight,
    /// A weight was greater than 1.0; propagation probabilities must be <= 1.
    WeightAboveOne,
    /// An edge points at a node that is not in the node set.
    UnknownTarget(NodeId),
    /// A node id contained an embedded control character.
    InvalidNodeId(NodeId),
    /// Graph contains zero nodes; the simulator cannot run on an empty graph.
    EmptyGraph,
}

/// Directed multi-edge graph over named nodes.
///
/// Topology is reproducible from `seed` alone (combined with the parameters
/// fed to [`ContagionGraph::generate_deterministic`]).
#[derive(Debug, Clone)]
pub struct ContagionGraph {
    nodes: Vec<NodeId>,
    edges: BTreeMap<NodeId, Vec<ContagionEdge>>,
    seed: u64,
}

/// Cap on per-node out-edges to bound memory in the long-running batch
/// sweep that sub-task 4 will exercise.
const MAX_EDGES_PER_NODE: usize = 4096;

/// Cap on total nodes in a single graph. Matches
/// `dgis::contagion_profiles::MAX_PROFILE_NODES` (the only non-test consumer
/// that already enforces this bound at the loader). Keeping the cap inside
/// `ContagionGraph` itself prevents a caller of `generate_deterministic` or
/// repeated `add_node` from bypassing the loader's check and ballooning memory.
const MAX_NODES: usize = 1024;

impl ContagionGraph {
    /// Construct an empty graph with the given seed. Intended for callers
    /// that build the graph node-by-node (used by campaign-profile loaders
    /// in sub-task 3).
    pub fn new(seed: u64) -> Self {
        Self {
            nodes: Vec::new(),
            edges: BTreeMap::new(),
            seed,
        }
    }

    /// Seed used to (re)generate this graph. Stable across clones so the
    /// later simulator can stamp it into reports for replay.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Snapshot view of all node ids in insertion order.
    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }

    /// Add a node. Idempotent: re-adding an existing id is a no-op.
    /// Also a no-op once the graph already holds `MAX_NODES` distinct nodes —
    /// this preserves the fire-and-forget API while bounding memory against
    /// callers that bypass the profile loader's check.
    pub fn add_node(&mut self, node: NodeId) {
        if validate_node_id(&node).is_err() {
            return;
        }
        if !self.edges.contains_key(&node) {
            if self.nodes.len() >= MAX_NODES {
                return;
            }
            self.nodes.push(node.clone());
            self.edges.insert(node, Vec::new());
        }
    }

    /// Add an edge, validating weight finiteness and target existence.
    pub fn add_edge(&mut self, source: &NodeId, edge: ContagionEdge) -> Result<(), GraphError> {
        validate_node_id(source)?;
        validate_node_id(&edge.target)?;
        if !edge.weight.is_finite() {
            return Err(GraphError::NonFiniteWeight);
        }
        if edge.weight < 0.0 {
            return Err(GraphError::NegativeWeight);
        }
        if edge.weight > 1.0 {
            return Err(GraphError::WeightAboveOne);
        }
        if !self.edges.contains_key(source) {
            return Err(GraphError::UnknownTarget(source.clone()));
        }
        if !self.edges.contains_key(&edge.target) {
            return Err(GraphError::UnknownTarget(edge.target.clone()));
        }
        let bucket = self.edges.entry(source.clone()).or_default();
        crate::push_bounded(bucket, edge, MAX_EDGES_PER_NODE);
        Ok(())
    }

    /// Return the out-edges for `node`. Returns an empty slice for unknown
    /// nodes — callers should `validate()` first if they require strict
    /// membership semantics.
    pub fn neighbors(&self, node: &NodeId) -> &[ContagionEdge] {
        self.edges.get(node).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Total directed edge count.
    pub fn edge_count(&self) -> usize {
        let mut total: usize = 0;
        for bucket in self.edges.values() {
            total = total.saturating_add(bucket.len());
        }
        total
    }

    /// Verify graph invariants:
    ///
    /// * graph is non-empty
    /// * every edge weight is finite and non-negative
    /// * every edge target is in the node set
    pub fn validate(&self) -> Result<(), GraphError> {
        if self.nodes.is_empty() {
            return Err(GraphError::EmptyGraph);
        }
        for node in &self.nodes {
            validate_node_id(node)?;
        }
        let known: BTreeSet<&NodeId> = self.edges.keys().collect();
        for (source, bucket) in &self.edges {
            validate_node_id(source)?;
            for edge in bucket {
                validate_node_id(&edge.target)?;
                if !edge.weight.is_finite() {
                    return Err(GraphError::NonFiniteWeight);
                }
                if edge.weight < 0.0 {
                    return Err(GraphError::NegativeWeight);
                }
                if edge.weight > 1.0 {
                    return Err(GraphError::WeightAboveOne);
                }
                if !known.contains(&edge.target) {
                    return Err(GraphError::UnknownTarget(edge.target.clone()));
                }
            }
        }
        Ok(())
    }

    /// Deterministically generate a contagion graph topology.
    ///
    /// Given the same `seed`, `n_nodes`, and `edge_density`, this returns a
    /// byte-identical graph. Density is clamped to `[0.0, 1.0]` after a
    /// finiteness check.
    ///
    /// Node ids are emitted as `"n{i:08}"` so they sort lexicographically the
    /// same way they sort numerically — important for stable BTreeMap-driven
    /// iteration order in later simulator output.
    pub fn generate_deterministic(seed: u64, n_nodes: usize, edge_density: f64) -> Self {
        let density = if edge_density.is_finite() {
            edge_density.clamp(0.0, 1.0)
        } else {
            0.0
        };

        // Clamp before the loop so the edge-generation phase below cannot
        // index past the actual `graph.nodes` length (add_node silently
        // refuses past MAX_NODES, which would otherwise leave src_idx /
        // dst_idx pointing at missing entries).
        let n_nodes = n_nodes.min(MAX_NODES);
        let mut graph = Self::new(seed);
        for i in 0..n_nodes {
            graph.add_node(format!("n{:08}", i));
        }

        if n_nodes < 2 {
            return graph;
        }

        // SplitMix64 keyed off `seed` ⊕ a domain separator constant so two
        // different deterministic streams (e.g. node ordering vs. edge
        // weighting in sub-task 2) cannot accidentally coincide.
        let mut rng = SplitMix64::new(seed ^ 0x4447_4953_4347_5048); // "DGISCGPH"

        for src_idx in 0..n_nodes {
            for dst_idx in 0..n_nodes {
                if src_idx == dst_idx {
                    continue;
                }
                let roll = rng.next_unit_f64();
                if roll >= density {
                    continue;
                }
                // Weight in [0.05, 1.0] so we never emit a 0.0 edge that
                // would silently no-op in the propagation step later.
                let weight_raw = rng.next_unit_f64();
                let weight = 0.05_f64 + (weight_raw * 0.95_f64);
                let weight = if weight.is_finite() {
                    weight.clamp(0.0, 1.0)
                } else {
                    0.05
                };
                // Distribute edge kinds across the four variants using two
                // bits of the next draw so kind selection is also seeded.
                let kind_bits = rng.next_u64() & 0b11;
                let edge_kind = match kind_bits {
                    0 => EdgeKind::DependencyImport,
                    1 => EdgeKind::MaintainerOverlap,
                    2 => EdgeKind::OrgOverlap,
                    _ => EdgeKind::NamespaceShadow,
                };
                let src = graph.nodes[src_idx].clone();
                let target = graph.nodes[dst_idx].clone();
                // Both endpoints came from `graph.nodes`, so add_edge can
                // only fail on the (already filtered) weight checks.
                let _ = graph.add_edge(
                    &src,
                    ContagionEdge {
                        target,
                        weight,
                        edge_kind,
                    },
                );
            }
        }
        graph
    }
}

/// SplitMix64 deterministic PRNG. Tiny, dependency-free, well-distributed
/// for non-cryptographic seeding. Used here strictly for topology
/// generation; a future cryptographic-grade RNG can replace this without
/// changing the public API.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // Standard SplitMix64 constants from Steele/Lea/Flood 2014.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform `f64` in `[0.0, 1.0)`. Guaranteed finite.
    fn next_unit_f64(&mut self) -> f64 {
        // Top 53 bits over 2^53 — the standard double-precision unit draw.
        let bits = self.next_u64() >> 11;
        (bits as f64) / ((1u64 << 53) as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_produces_identical_graph() {
        let a = ContagionGraph::generate_deterministic(0xDEAD_BEEF, 16, 0.25);
        let b = ContagionGraph::generate_deterministic(0xDEAD_BEEF, 16, 0.25);
        assert_eq!(a.seed(), b.seed());
        assert_eq!(a.nodes(), b.nodes());
        assert_eq!(a.edge_count(), b.edge_count());
        for n in a.nodes() {
            assert_eq!(a.neighbors(n), b.neighbors(n));
        }
    }

    #[test]
    fn different_seeds_produce_different_graphs() {
        let a = ContagionGraph::generate_deterministic(1, 24, 0.5);
        let b = ContagionGraph::generate_deterministic(2, 24, 0.5);
        // Node sets are identical (same n_nodes) but edge structure must differ
        // for at least one node — otherwise the seed had no effect.
        let mut any_diff = false;
        for n in a.nodes() {
            if a.neighbors(n) != b.neighbors(n) {
                any_diff = true;
                break;
            }
        }
        assert!(any_diff, "seed change must perturb edge structure");
    }

    #[test]
    fn all_generated_weights_are_finite_and_in_range() {
        let g = ContagionGraph::generate_deterministic(42, 32, 0.4);
        let mut seen = 0usize;
        for n in g.nodes() {
            for e in g.neighbors(n) {
                assert!(e.weight.is_finite(), "weight must be finite");
                assert!(
                    e.weight >= 0.0 && e.weight <= 1.0,
                    "weight {} out of [0,1]",
                    e.weight
                );
                seen += 1;
            }
        }
        assert_eq!(seen, g.edge_count());
        assert!(
            g.edge_count() > 0,
            "density 0.4 over 32 nodes should yield edges"
        );
    }

    #[test]
    fn validate_rejects_nan_weight() -> Result<(), String> {
        let mut g = ContagionGraph::new(7);
        g.add_node("a".to_string());
        g.add_node("b".to_string());
        // Bypass the constructor to inject a NaN and ensure validate() catches it.
        let bucket = g
            .edges
            .get_mut("a")
            .ok_or_else(|| "expected node `a` bucket".to_string())?;
        bucket.push(ContagionEdge {
            target: "b".to_string(),
            weight: f64::NAN,
            edge_kind: EdgeKind::DependencyImport,
        });
        assert_eq!(g.validate(), Err(GraphError::NonFiniteWeight));
        Ok(())
    }

    #[test]
    fn validate_rejects_unknown_target() -> Result<(), String> {
        let mut g = ContagionGraph::new(7);
        g.add_node("a".to_string());
        let bucket = g
            .edges
            .get_mut("a")
            .ok_or_else(|| "expected node `a` bucket".to_string())?;
        bucket.push(ContagionEdge {
            target: "ghost".to_string(),
            weight: 0.5,
            edge_kind: EdgeKind::OrgOverlap,
        });
        match g.validate() {
            Err(GraphError::UnknownTarget(t)) => assert_eq!(t, "ghost"),
            other => return Err(format!("expected UnknownTarget, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn node_ids_reject_embedded_nuls() -> Result<(), String> {
        let bad = "pkg\0shadow".to_string();
        assert_eq!(
            ContagionEdge::new(bad.clone(), 0.5, EdgeKind::DependencyImport).err(),
            Some(GraphError::InvalidNodeId(bad.clone()))
        );

        let mut g = ContagionGraph::new(17);
        g.add_node(bad.clone());
        assert!(g.nodes().is_empty(), "invalid node id must not enter graph");

        g.add_node("a".to_string());
        g.add_node("b".to_string());
        let valid_edge = ContagionEdge::new("b".to_string(), 0.5, EdgeKind::DependencyImport)
            .map_err(|e| format!("valid edge rejected: {e:?}"))?;
        assert_eq!(
            g.add_edge(&bad, valid_edge).err(),
            Some(GraphError::InvalidNodeId(bad.clone()))
        );
        assert_eq!(
            g.add_edge(
                &"a".to_string(),
                ContagionEdge {
                    target: bad.clone(),
                    weight: 0.5,
                    edge_kind: EdgeKind::DependencyImport,
                },
            )
            .err(),
            Some(GraphError::InvalidNodeId(bad))
        );
        Ok(())
    }

    #[test]
    fn validate_rejects_corrupted_null_byte_node_ids() {
        let bad = "pkg\0shadow".to_string();
        let mut g = ContagionGraph::new(19);
        g.nodes.push(bad.clone());
        g.edges.insert(bad.clone(), Vec::new());
        assert_eq!(g.validate(), Err(GraphError::InvalidNodeId(bad)));
    }

    #[test]
    fn node_ids_reject_control_characters() -> Result<(), String> {
        let bad = "pkg\nshadow".to_string();
        assert_eq!(
            ContagionEdge::new(bad.clone(), 0.5, EdgeKind::DependencyImport).err(),
            Some(GraphError::InvalidNodeId(bad.clone()))
        );

        let mut g = ContagionGraph::new(23);
        g.add_node(bad.clone());
        assert!(
            g.nodes().is_empty(),
            "control-character node id must not enter graph"
        );

        g.add_node("a".to_string());
        g.add_node("b".to_string());
        let valid_edge = ContagionEdge::new("b".to_string(), 0.5, EdgeKind::DependencyImport)
            .map_err(|e| format!("valid edge rejected: {e:?}"))?;
        assert_eq!(
            g.add_edge(&bad, valid_edge).err(),
            Some(GraphError::InvalidNodeId(bad.clone()))
        );
        Ok(())
    }

    #[test]
    fn node_ids_reject_empty_and_padded_identifiers() -> Result<(), String> {
        for bad in ["", " ", " pkg", "pkg "] {
            let bad = bad.to_string();
            assert_eq!(
                ContagionEdge::new(bad.clone(), 0.5, EdgeKind::DependencyImport).err(),
                Some(GraphError::InvalidNodeId(bad.clone()))
            );

            let mut g = ContagionGraph::new(24);
            g.add_node(bad.clone());
            assert!(
                g.nodes().is_empty(),
                "empty or padded node id must not enter graph"
            );

            g.add_node("a".to_string());
            g.add_node("b".to_string());
            let valid_edge = ContagionEdge::new("b".to_string(), 0.5, EdgeKind::DependencyImport)
                .map_err(|e| format!("valid edge rejected: {e:?}"))?;
            assert_eq!(
                g.add_edge(&bad, valid_edge).err(),
                Some(GraphError::InvalidNodeId(bad.clone()))
            );
        }
        Ok(())
    }

    #[test]
    fn validate_rejects_corrupted_control_character_node_ids() {
        let bad = "pkg\nshadow".to_string();
        let mut g = ContagionGraph::new(29);
        g.nodes.push(bad.clone());
        g.edges.insert(bad.clone(), Vec::new());
        assert_eq!(g.validate(), Err(GraphError::InvalidNodeId(bad)));
    }

    #[test]
    fn neighbors_returns_correct_edges() {
        let mut g = ContagionGraph::new(11);
        g.add_node("a".to_string());
        g.add_node("b".to_string());
        g.add_node("c".to_string());
        g.add_edge(
            &"a".to_string(),
            ContagionEdge::new("b".to_string(), 0.3, EdgeKind::DependencyImport).unwrap(),
        )
        .unwrap();
        g.add_edge(
            &"a".to_string(),
            ContagionEdge::new("c".to_string(), 0.7, EdgeKind::MaintainerOverlap).unwrap(),
        )
        .unwrap();
        let a_nbrs = g.neighbors(&"a".to_string());
        assert_eq!(a_nbrs.len(), 2);
        assert_eq!(a_nbrs[0].target, "b");
        assert_eq!(a_nbrs[1].target, "c");
        assert_eq!(g.neighbors(&"b".to_string()).len(), 0);
        // Unknown node returns empty slice, not panic.
        assert_eq!(g.neighbors(&"missing".to_string()).len(), 0);
    }

    #[test]
    fn edge_count_matches_inserted_edges() {
        let mut g = ContagionGraph::new(13);
        for id in ["a", "b", "c", "d"] {
            g.add_node(id.to_string());
        }
        let inserts = [
            ("a", "b", EdgeKind::DependencyImport),
            ("a", "c", EdgeKind::NamespaceShadow),
            ("b", "d", EdgeKind::OrgOverlap),
            ("c", "d", EdgeKind::MaintainerOverlap),
            ("d", "a", EdgeKind::DependencyImport),
        ];
        for (src, dst, kind) in inserts {
            g.add_edge(
                &src.to_string(),
                ContagionEdge::new(dst.to_string(), 0.5, kind).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(g.edge_count(), 5);
        assert!(g.validate().is_ok());
    }

    #[test]
    fn empty_graph_validate_errors_but_generate_with_zero_is_safe() {
        let g = ContagionGraph::new(0);
        assert_eq!(g.validate(), Err(GraphError::EmptyGraph));
        assert_eq!(g.edge_count(), 0);
        // generate_deterministic with n_nodes=0 should be safe (no edges, no panics).
        let g0 = ContagionGraph::generate_deterministic(99, 0, 0.5);
        assert_eq!(g0.edge_count(), 0);
        assert_eq!(g0.nodes().len(), 0);
        assert_eq!(g0.validate(), Err(GraphError::EmptyGraph));
        // n_nodes=1 yields no edges (no self-loops) but is non-empty.
        let g1 = ContagionGraph::generate_deterministic(99, 1, 1.0);
        assert_eq!(g1.nodes().len(), 1);
        assert_eq!(g1.edge_count(), 0);
        assert!(g1.validate().is_ok());
    }

    #[test]
    fn edge_constructor_rejects_non_finite_and_negative() {
        assert_eq!(
            ContagionEdge::new("x".to_string(), f64::NAN, EdgeKind::OrgOverlap).err(),
            Some(GraphError::NonFiniteWeight)
        );
        assert_eq!(
            ContagionEdge::new("x".to_string(), f64::INFINITY, EdgeKind::OrgOverlap).err(),
            Some(GraphError::NonFiniteWeight)
        );
        assert_eq!(
            ContagionEdge::new("x".to_string(), -0.001, EdgeKind::OrgOverlap).err(),
            Some(GraphError::NegativeWeight)
        );
        assert_eq!(
            ContagionEdge::new("x".to_string(), 1.001, EdgeKind::OrgOverlap).err(),
            Some(GraphError::WeightAboveOne)
        );
        assert!(ContagionEdge::new("x".to_string(), 0.0, EdgeKind::OrgOverlap).is_ok());
        assert!(ContagionEdge::new("x".to_string(), 1.0, EdgeKind::OrgOverlap).is_ok());
    }

    #[test]
    fn validate_rejects_corrupted_weight_above_one() -> Result<(), String> {
        let mut g = ContagionGraph::new(7);
        g.add_node("a".to_string());
        g.add_node("b".to_string());
        let bucket = g
            .edges
            .get_mut("a")
            .ok_or_else(|| "expected node `a` bucket".to_string())?;
        bucket.push(ContagionEdge {
            target: "b".to_string(),
            weight: 1.001,
            edge_kind: EdgeKind::DependencyImport,
        });
        assert_eq!(g.validate(), Err(GraphError::WeightAboveOne));
        Ok(())
    }

    #[test]
    fn add_edge_rejects_unknown_endpoints() {
        let mut g = ContagionGraph::new(5);
        g.add_node("only".to_string());
        let edge =
            ContagionEdge::new("missing".to_string(), 0.5, EdgeKind::DependencyImport).unwrap();
        let err = g.add_edge(&"only".to_string(), edge).unwrap_err();
        assert!(matches!(err, GraphError::UnknownTarget(_)));
        // Unknown source.
        let edge2 =
            ContagionEdge::new("only".to_string(), 0.5, EdgeKind::DependencyImport).unwrap();
        let err2 = g.add_edge(&"phantom".to_string(), edge2).unwrap_err();
        assert!(matches!(err2, GraphError::UnknownTarget(_)));
    }

    #[test]
    fn density_clamped_to_unit_interval() {
        // Density above 1.0 must clamp (not panic, not produce infinities).
        let g = ContagionGraph::generate_deterministic(123, 8, 5.0);
        assert!(g.validate().is_ok());
        // density >= 1.0 means every (src,dst) with src!=dst is an edge:
        // n_nodes * (n_nodes - 1) = 8 * 7 = 56.
        assert_eq!(g.edge_count(), 56);
        // NaN density coerces to 0 → no edges.
        let g_nan = ContagionGraph::generate_deterministic(123, 8, f64::NAN);
        assert_eq!(g_nan.edge_count(), 0);
    }
}
