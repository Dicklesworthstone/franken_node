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

use super::node_interner::{NodeId as InternedNodeId, NodeInterner};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide counter incremented every time a `ContagionGraph` is
/// constructed via `ContagionGraph::new` (which is the single entry point
/// used by both direct callers and `ContagionGraph::generate_deterministic`).
///
/// Exposed via [`graph_constructions_total`] for the franken-node ops
/// metric renderer. Counts since process start; not reset on snapshot.
/// Per bd-98xo5.5.5, the ratio of
/// `franken_node_dgis_simulation_steps_total /
/// franken_node_dgis_graph_constructions_total` tells the perf team
/// whether construction or simulation dominates production load, which
/// in turn validates the effort budget for the NodeId interning work
/// proposed under bd-98xo5.5.
static GRAPH_CONSTRUCTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Read the process-wide DGIS graph-construction counter. Used by the
/// ops metric renderer to emit `franken_node_dgis_graph_constructions_total`.
#[must_use]
pub fn graph_constructions_total() -> u64 {
    GRAPH_CONSTRUCTIONS_TOTAL.load(Ordering::Relaxed)
}

/// Stable, human-readable identifier used at public API boundaries.
///
/// `ContagionGraph` stores membership and edge buckets as interned `u32` ids
/// internally, but simulator/profile callers still pass and receive the
/// original string form until the sibling DGIS migration beads move them.
pub type NodeId = String;

/// Validate a node id before it enters the graph.
///
/// Node ids are surfaced in fixture paths, reports, and operator output.
/// Rejecting control characters at the graph boundary prevents downstream path
/// and display layers from seeing split identifiers or injected output lines.
pub fn validate_node_id(node: &str) -> Result<(), GraphError> {
    // Length check first and avoid cloning the attacker-controlled payload into
    // the error, otherwise overlong rejection still preserves an O(N) path.
    if node.len() > MAX_NODE_ID_LEN {
        return Err(overlong_node_id_error());
    }
    let trimmed = node.trim();
    if trimmed.is_empty() || node != trimmed || node.chars().any(char::is_control) {
        return Err(GraphError::InvalidNodeId(node.to_string()));
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

#[derive(Debug, Clone, Copy, PartialEq)]
struct InternedContagionEdge {
    target: InternedNodeId,
    weight: f64,
    edge_kind: EdgeKind,
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
    interner: NodeInterner,
    nodes: Vec<NodeId>,
    nodes_internal: BTreeSet<InternedNodeId>,
    edges: BTreeMap<InternedNodeId, Vec<InternedContagionEdge>>,
    neighbor_views: BTreeMap<InternedNodeId, Vec<ContagionEdge>>,
    seed: u64,
}

/// Cap on per-node out-edges to bound memory in the long-running batch
/// sweep that sub-task 4 will exercise.
const MAX_EDGES_PER_NODE: usize = 4096;

/// Maximum length of a node ID string in bytes. Real package names and
/// identifiers are far shorter; the cap prevents DoS via multi-megabyte
/// node ID strings that would exhaust memory or slow string operations.
const MAX_NODE_ID_LEN: usize = 512;

fn overlong_node_id_error() -> GraphError {
    GraphError::InvalidNodeId(format!("node id exceeds {MAX_NODE_ID_LEN} bytes"))
}

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
        // Track graph constructions for the bd-98xo5.5.5 perf-budget
        // measurement. `generate_deterministic` goes through this
        // constructor so a single counter site covers both entry points.
        GRAPH_CONSTRUCTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
        Self {
            interner: NodeInterner::new(),
            nodes: Vec::new(),
            nodes_internal: BTreeSet::new(),
            edges: BTreeMap::new(),
            neighbor_views: BTreeMap::new(),
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

    fn member_id_for(&self, node: &str) -> Option<InternedNodeId> {
        self.interner
            .get(node)
            .filter(|id| self.nodes_internal.contains(id))
    }

    fn unknown_target_for(&self, id: InternedNodeId) -> GraphError {
        GraphError::UnknownTarget(
            self.interner
                .resolve(id)
                .map(str::to_string)
                .unwrap_or_else(|| format!("<interned-node:{}>", id.as_u32())),
        )
    }

    /// Add a node. Idempotent: re-adding an existing id is a no-op.
    /// Also a no-op once the graph already holds `MAX_NODES` distinct nodes —
    /// this preserves the fire-and-forget API while bounding memory against
    /// callers that bypass the profile loader's check.
    pub fn add_node(&mut self, node: NodeId) {
        if validate_node_id(&node).is_err() {
            return;
        }
        if self.member_id_for(&node).is_some() {
            return;
        }
        if self.nodes.len() >= MAX_NODES {
            return;
        }
        let Ok(node_id) = self.interner.intern(&node) else {
            return;
        };
        if self.nodes_internal.insert(node_id) {
            self.nodes.push(node);
            self.edges.insert(node_id, Vec::new());
            self.neighbor_views.insert(node_id, Vec::new());
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
        let source_id = self
            .member_id_for(source)
            .ok_or_else(|| GraphError::UnknownTarget(source.clone()))?;
        let target_id = self
            .member_id_for(&edge.target)
            .ok_or_else(|| GraphError::UnknownTarget(edge.target.clone()))?;

        let internal_edge = InternedContagionEdge {
            target: target_id,
            weight: edge.weight,
            edge_kind: edge.edge_kind,
        };
        let bucket = self.edges.entry(source_id).or_default();
        crate::push_bounded(bucket, internal_edge, MAX_EDGES_PER_NODE);
        let view_bucket = self.neighbor_views.entry(source_id).or_default();
        crate::push_bounded(view_bucket, edge, MAX_EDGES_PER_NODE);
        Ok(())
    }

    /// Return the out-edges for `node`. Returns an empty slice for unknown
    /// nodes — callers should `validate()` first if they require strict
    /// membership semantics.
    pub fn neighbors(&self, node: &NodeId) -> &[ContagionEdge] {
        self.member_id_for(node)
            .and_then(|node_id| self.neighbor_views.get(&node_id))
            .map(Vec::as_slice)
            .unwrap_or(&[])
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
            if self.member_id_for(node).is_none() {
                return Err(GraphError::UnknownTarget(node.clone()));
            }
        }
        let known = &self.nodes_internal;
        for source_id in known {
            let source = self
                .interner
                .resolve(*source_id)
                .ok_or_else(|| self.unknown_target_for(*source_id))?;
            validate_node_id(source)?;
        }
        for (source_id, bucket) in &self.edges {
            if !known.contains(source_id) {
                return Err(self.unknown_target_for(*source_id));
            }
            let source = self
                .interner
                .resolve(*source_id)
                .ok_or_else(|| self.unknown_target_for(*source_id))?;
            validate_node_id(source)?;
            for edge in bucket {
                if !edge.weight.is_finite() {
                    return Err(GraphError::NonFiniteWeight);
                }
                if edge.weight < 0.0 {
                    return Err(GraphError::NegativeWeight);
                }
                if edge.weight > 1.0 {
                    return Err(GraphError::WeightAboveOne);
                }
                debug_assert!(matches!(
                    edge.edge_kind,
                    EdgeKind::DependencyImport
                        | EdgeKind::MaintainerOverlap
                        | EdgeKind::OrgOverlap
                        | EdgeKind::NamespaceShadow
                ));
                let target = self
                    .interner
                    .resolve(edge.target)
                    .ok_or_else(|| self.unknown_target_for(edge.target))?;
                validate_node_id(target)?;
                if !known.contains(&edge.target) {
                    return Err(GraphError::UnknownTarget(target.to_string()));
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
                let Some(src) = graph.nodes.get(src_idx).cloned() else {
                    continue;
                };
                let Some(target) = graph.nodes.get(dst_idx).cloned() else {
                    continue;
                };
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

    fn push_corrupted_internal_edge(
        graph: &mut ContagionGraph,
        source: &str,
        target: &str,
        weight: f64,
        edge_kind: EdgeKind,
    ) -> Result<(), String> {
        let source_id = graph
            .member_id_for(source)
            .ok_or_else(|| format!("expected source node `{source}`"))?;
        let target_id = match graph.member_id_for(target) {
            Some(id) => id,
            None => graph
                .interner
                .intern(target)
                .map_err(|err| format!("failed to intern target `{target}`: {err}"))?,
        };
        let bucket = graph
            .edges
            .get_mut(&source_id)
            .ok_or_else(|| format!("expected node `{source}` bucket"))?;
        bucket.push(InternedContagionEdge {
            target: target_id,
            weight,
            edge_kind,
        });
        Ok(())
    }

    /// Regression for bd-98xo5.5.5: `ContagionGraph::new` and
    /// `ContagionGraph::generate_deterministic` (which delegates to
    /// `new`) MUST both increment
    /// `franken_node_dgis_graph_constructions_total` by exactly 1 each
    /// time they run, so the ratio metric documented above accurately
    /// reflects production load. Snapshot the counter before/after to
    /// stay robust against parallel test schedulers running in the same
    /// process address space.
    #[test]
    fn graph_constructions_total_increments_on_new_and_generate_deterministic_bd98xo5_5_5() {
        let baseline = graph_constructions_total();

        let _direct = ContagionGraph::new(0xC0FFEE);
        let after_new = graph_constructions_total();
        assert!(
            after_new >= baseline + 1,
            "ContagionGraph::new must bump the construction counter; baseline={baseline}, after={after_new}"
        );

        let _generated = ContagionGraph::generate_deterministic(0xBAD_F00D, 4, 0.25);
        let after_generate = graph_constructions_total();
        assert!(
            after_generate >= after_new + 1,
            "generate_deterministic must bump the construction counter via Self::new; after_new={after_new}, after_generate={after_generate}"
        );
    }

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
        push_corrupted_internal_edge(&mut g, "a", "b", f64::NAN, EdgeKind::DependencyImport)?;
        assert_eq!(g.validate(), Err(GraphError::NonFiniteWeight));
        Ok(())
    }

    #[test]
    fn validate_rejects_unknown_target() -> Result<(), String> {
        let mut g = ContagionGraph::new(7);
        g.add_node("a".to_string());
        push_corrupted_internal_edge(&mut g, "a", "ghost", 0.5, EdgeKind::OrgOverlap)?;
        match g.validate() {
            Err(GraphError::UnknownTarget(t)) => assert_eq!(t, "ghost"),
            other => return Err(format!("expected UnknownTarget, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn graph_nodes_iter_matches_legacy_string_view() {
        let mut graph = ContagionGraph::new(31);
        for node in ["pkg:root", "pkg:dep-a", "pkg:dep-b"] {
            graph.add_node(node.to_string());
        }

        assert_eq!(
            graph.nodes(),
            &[
                "pkg:root".to_string(),
                "pkg:dep-a".to_string(),
                "pkg:dep-b".to_string()
            ]
        );
    }

    #[test]
    fn graph_add_edge_with_intern_creates_correct_adjacency() -> Result<(), String> {
        let mut graph = ContagionGraph::new(37);
        graph.add_node("pkg:root".to_string());
        graph.add_node("pkg:dep-a".to_string());
        graph.add_node("pkg:dep-b".to_string());

        graph
            .add_edge(
                &"pkg:root".to_string(),
                ContagionEdge::new("pkg:dep-a".to_string(), 0.75, EdgeKind::DependencyImport)
                    .map_err(|err| format!("edge rejected: {err:?}"))?,
            )
            .map_err(|err| format!("add edge dep-a failed: {err:?}"))?;
        graph
            .add_edge(
                &"pkg:root".to_string(),
                ContagionEdge::new("pkg:dep-b".to_string(), 0.25, EdgeKind::MaintainerOverlap)
                    .map_err(|err| format!("edge rejected: {err:?}"))?,
            )
            .map_err(|err| format!("add edge dep-b failed: {err:?}"))?;

        let root = "pkg:root".to_string();
        let neighbors = graph.neighbors(&root);
        assert_eq!(neighbors.len(), 2);
        assert_eq!(neighbors[0].target, "pkg:dep-a");
        assert_eq!(neighbors[0].weight, 0.75);
        assert_eq!(neighbors[0].edge_kind, EdgeKind::DependencyImport);
        assert_eq!(neighbors[1].target, "pkg:dep-b");
        assert_eq!(neighbors[1].weight, 0.25);
        assert_eq!(neighbors[1].edge_kind, EdgeKind::MaintainerOverlap);
        assert_eq!(graph.edge_count(), 2);
        Ok(())
    }

    #[test]
    fn graph_validate_rejects_dangling_edge() -> Result<(), String> {
        let mut graph = ContagionGraph::new(41);
        graph.add_node("pkg:root".to_string());
        push_corrupted_internal_edge(
            &mut graph,
            "pkg:root",
            "pkg:ghost",
            0.5,
            EdgeKind::NamespaceShadow,
        )?;

        assert_eq!(
            graph.validate(),
            Err(GraphError::UnknownTarget("pkg:ghost".to_string()))
        );
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
        assert_eq!(g.validate(), Err(GraphError::InvalidNodeId(bad)));
    }

    #[test]
    fn node_ids_reject_overlong_identifiers() -> Result<(), String> {
        // Node IDs exceeding MAX_NODE_ID_LEN must be rejected to prevent DoS
        // via multi-megabyte strings exhausting memory or slowing operations.
        let overlong = "x".repeat(MAX_NODE_ID_LEN + 1);
        assert_eq!(validate_node_id(&overlong), Err(overlong_node_id_error()));
        let rejected = match validate_node_id(&overlong) {
            Err(GraphError::InvalidNodeId(rejected)) => rejected,
            other => {
                return Err(format!(
                    "expected overlong InvalidNodeId rejection, got {other:?}"
                ));
            }
        };
        assert!(
            rejected.len() < overlong.len(),
            "overlong rejection must not clone the attacker-controlled payload"
        );

        // Edge construction must also reject overlong target IDs
        assert_eq!(
            ContagionEdge::new(overlong.clone(), 0.5, EdgeKind::DependencyImport).err(),
            Some(overlong_node_id_error())
        );

        // Graph add_node must silently reject overlong IDs
        let mut g = ContagionGraph::new(31);
        g.add_node(overlong.clone());
        assert!(
            g.nodes().is_empty(),
            "overlong node id must not enter graph"
        );

        // Exactly MAX_NODE_ID_LEN should be accepted
        let at_limit = "y".repeat(MAX_NODE_ID_LEN);
        assert!(validate_node_id(&at_limit).is_ok());
        Ok(())
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
        push_corrupted_internal_edge(&mut g, "a", "b", 1.001, EdgeKind::DependencyImport)?;
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
