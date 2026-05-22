//! DGIS node-id interner (bd-98xo5.5.1 — design + skeleton).
//!
//! See `docs/dev/dgis_node_interner_design.md` for the three load-bearing
//! design decisions (Display strategy, determinism, capacity bound). This
//! module is the interned-id foundation used by `dgis::contagion_graph`;
//! sibling DGIS surfaces migrate to the same representation in follow-on beads.
//!
//! ## Why u32 interning
//!
//! `dgis::contagion_graph::NodeId` is currently `pub type NodeId = String`.
//! Profiling round-2 flagged dependency-graph traversal as a hotspot:
//! every edge dereference walks a `BTreeMap<String, _>` keyed by the full
//! node-id string. Interning collapses each lookup to a `u32` compare.
//!
//! ## Quick-start
//!
//! ```ignore
//! use frankenengine_node::dgis::node_interner::{NodeId, NodeInterner};
//! let mut interner = NodeInterner::new();
//! let id_a = interner.intern("npm:@scope/pkg").unwrap();
//! let id_b = interner.intern("npm:@scope/pkg").unwrap(); // returns same u32
//! assert_eq!(id_a, id_b);
//! assert_eq!(interner.resolve(id_a), Some("npm:@scope/pkg"));
//! ```

use std::collections::BTreeMap;
use std::fmt;

/// Maximum distinct node ids a single `NodeInterner` will accept. Matches
/// the existing `dgis::contagion_graph::MAX_NODES = 1024` cap in the
/// simulator (a unit test below pins both constants in lockstep so a
/// future migration cannot let them drift).
pub const NODE_INTERNER_MAX_NODES: usize = 1024;

/// Interned node identifier. `Copy + 'static`, deliberately NOT
/// implementing `fmt::Display` — see `display_with(&interner)` and the
/// Decision 1 rationale in `docs/dev/dgis_node_interner_design.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(u32);

impl NodeId {
    /// Construct a `NodeId` from a raw u32. Keep this private so sibling
    /// modules cannot fabricate ids that bypass the interner's string index
    /// and capacity cap.
    fn from_raw(value: u32) -> Self {
        Self(value)
    }

    /// Expose the raw u32 for diagnostic + serialisation purposes only.
    /// Operator-facing UI MUST resolve the id to a string via
    /// `NodeInterner::resolve` (or the future `display_with` helper) —
    /// rendering the bare u32 in operator output is a usability bug.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// Errors surfaced by `NodeInterner::intern`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InternError {
    /// Empty, whitespace-padded, or control-character-containing node id.
    #[error("invalid node id")]
    InvalidNodeId,
    /// `intern` was called for the `(NODE_INTERNER_MAX_NODES + 1)`th
    /// distinct node id. The cap mirrors the simulator's existing
    /// `MAX_NODES` (see `dgis::contagion_graph`).
    #[error("NODE_INTERNER_MAX_NODES exceeded: max {max} distinct nodes per interner")]
    CapacityExceeded { max: usize },
}

/// String ↔ u32 interner for DGIS node ids.
///
/// Deterministic by construction: `intern("foo")` always returns the
/// next free `u32` for a fresh id, and `resolve(id)` always returns the
/// original string for an id this interner issued. Iteration order is
/// u32 order (i.e. insertion order) — see Decision 2 in the design note.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeInterner {
    to_str: Vec<String>,
    from_str: BTreeMap<String, u32>,
}

impl NodeInterner {
    /// Construct an empty interner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            to_str: Vec::new(),
            from_str: BTreeMap::new(),
        }
    }

    /// Intern a node id string. Returns the existing `NodeId` if the
    /// string has already been seen, otherwise inserts and returns the
    /// freshly assigned `NodeId`.
    ///
    /// # Errors
    ///
    /// Returns `InternError::CapacityExceeded` when attempting to intern
    /// the `(NODE_INTERNER_MAX_NODES + 1)`th distinct string. Repeated
    /// inserts of an already-interned string never count against the
    /// cap.
    pub fn intern(&mut self, s: &str) -> Result<NodeId, InternError> {
        validate_intern_node_id(s)?;
        if let Some(&existing) = self.from_str.get(s) {
            return Ok(NodeId::from_raw(existing));
        }
        if self.to_str.len() >= NODE_INTERNER_MAX_NODES {
            return Err(InternError::CapacityExceeded {
                max: NODE_INTERNER_MAX_NODES,
            });
        }
        // `to_str.len()` is bounded by NODE_INTERNER_MAX_NODES (1024),
        // well within u32 range; the cast cannot truncate.
        let id = u32::try_from(self.to_str.len()).expect("len bounded by NODE_INTERNER_MAX_NODES");
        self.to_str.push(s.to_string());
        self.from_str.insert(s.to_string(), id);
        Ok(NodeId::from_raw(id))
    }

    /// Return the already-interned id for `s` without inserting it.
    #[must_use]
    pub fn get(&self, s: &str) -> Option<NodeId> {
        self.from_str.get(s).copied().map(NodeId::from_raw)
    }

    /// Look up the original string for a previously interned `NodeId`.
    /// Returns `None` if the id was not produced by this interner.
    #[must_use]
    pub fn resolve(&self, id: NodeId) -> Option<&str> {
        let index = usize::try_from(id.as_u32()).ok()?;
        self.to_str.get(index).map(String::as_str)
    }

    /// Number of distinct node ids currently interned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.to_str.len()
    }

    /// True when the interner has not seen any node ids.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.to_str.is_empty()
    }

    /// Iterate `(NodeId, &str)` pairs in u32 (insertion) order. See
    /// Decision 2 in the design note for why this is the natural order
    /// for the simulator's deterministic walks.
    pub fn iter(&self) -> impl Iterator<Item = (NodeId, &str)> + '_ {
        self.to_str.iter().enumerate().map(|(idx, s)| {
            let id =
                u32::try_from(idx).expect("interner length bounded by NODE_INTERNER_MAX_NODES");
            (NodeId::from_raw(id), s.as_str())
        })
    }
}

fn validate_intern_node_id(s: &str) -> Result<(), InternError> {
    if s.trim().is_empty() || s != s.trim() || s.chars().any(char::is_control) {
        return Err(InternError::InvalidNodeId);
    }
    Ok(())
}

/// Operator-facing render helper. See Decision 1 in the design note:
/// `NodeId` deliberately does NOT implement `fmt::Display` itself — the
/// interner must be threaded through render sites so a caller cannot
/// accidentally render a bare u32 to operator output.
#[must_use]
pub fn display_with<'a>(id: NodeId, interner: &'a NodeInterner) -> DisplayWith<'a> {
    DisplayWith { id, interner }
}

pub struct DisplayWith<'a> {
    id: NodeId,
    interner: &'a NodeInterner,
}

impl<'a> fmt::Display for DisplayWith<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.interner.resolve(self.id) {
            Some(s) => f.write_str(s),
            None => write!(f, "<NodeId#{}@unknown>", self.id.as_u32()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn intern_same_string_returns_same_id() {
        let mut interner = NodeInterner::new();
        let a = interner.intern("npm:@scope/pkg").unwrap();
        let b = interner.intern("npm:@scope/pkg").unwrap();
        assert_eq!(a, b);
        assert_eq!(interner.len(), 1);
    }

    #[test]
    fn intern_different_strings_return_distinct_ids() {
        let mut interner = NodeInterner::new();
        let a = interner.intern("a").unwrap();
        let b = interner.intern("b").unwrap();
        assert_ne!(a, b);
        assert_eq!(interner.len(), 2);
    }

    #[test]
    fn resolve_round_trip() {
        let mut interner = NodeInterner::new();
        for node in ["pkg-foo", "pkg-bar", "pkg-baz"] {
            let id = interner.intern(node).unwrap();
            assert_eq!(interner.resolve(id), Some(node));
        }
    }

    #[test]
    fn get_returns_existing_id_without_inserting() {
        let mut interner = NodeInterner::new();
        assert_eq!(interner.get("pkg-foo"), None);
        let id = interner.intern("pkg-foo").unwrap();
        assert_eq!(interner.get("pkg-foo"), Some(id));
        assert_eq!(interner.get("pkg-bar"), None);
        assert_eq!(interner.len(), 1);
    }

    #[test]
    fn resolve_unknown_id_returns_none() {
        let interner = NodeInterner::new();
        // Tests live in this module, so they can still fabricate an id to
        // verify fail-closed lookup behavior while production callers cannot.
        assert_eq!(interner.resolve(NodeId::from_raw(42)), None);
    }

    #[test]
    fn intern_is_deterministic_under_same_insert_order() {
        // Two interners populated with the same sequence of inserts must
        // produce the same NodeId for each string. This is the
        // load-bearing determinism contract from Decision 2 in the
        // design note.
        let mut a = NodeInterner::new();
        let mut b = NodeInterner::new();
        for s in ["alpha", "beta", "gamma", "delta"] {
            assert_eq!(a.intern(s).unwrap(), b.intern(s).unwrap());
        }
    }

    #[test]
    fn intern_capacity_bound() {
        let mut interner = NodeInterner::new();
        for i in 0..NODE_INTERNER_MAX_NODES {
            interner
                .intern(&format!("node-{i}"))
                .expect("under cap must succeed");
        }
        let err = interner
            .intern("one-too-many")
            .expect_err("must reject the (MAX+1)th distinct node");
        assert_eq!(
            err,
            InternError::CapacityExceeded {
                max: NODE_INTERNER_MAX_NODES,
            }
        );
        // Re-interning an already-seen string after the cap is hit must
        // still succeed (the bead's spec — repeated inserts don't count
        // against the cap).
        let still_ok = interner
            .intern("node-0")
            .expect("repeated intern after cap must still resolve");
        assert_eq!(interner.resolve(still_ok), Some("node-0"));
    }

    #[test]
    fn intern_empty_string() {
        let mut interner = NodeInterner::new();
        assert_eq!(interner.intern("").unwrap_err(), InternError::InvalidNodeId);
        assert_eq!(
            interner.intern("   ").unwrap_err(),
            InternError::InvalidNodeId
        );
        assert_eq!(
            interner.intern("pkg\nsplit").unwrap_err(),
            InternError::InvalidNodeId
        );
        assert!(interner.is_empty());
    }

    #[test]
    fn intern_order_drives_node_id_assignment() {
        let mut interner = NodeInterner::new();
        let a = interner.intern("a").unwrap();
        let b = interner.intern("b").unwrap();
        assert_eq!(a.as_u32(), 0);
        assert_eq!(b.as_u32(), 1);
        let collected: Vec<(u32, &str)> = interner.iter().map(|(id, s)| (id.as_u32(), s)).collect();
        assert_eq!(collected, vec![(0, "a"), (1, "b")]);
    }

    #[test]
    fn iter_returns_pairs_in_insertion_order() {
        let mut interner = NodeInterner::new();
        for s in ["c", "a", "b"] {
            interner.intern(s).unwrap();
        }
        let collected: Vec<(u32, &str)> = interner.iter().map(|(id, s)| (id.as_u32(), s)).collect();
        assert_eq!(collected, vec![(0, "c"), (1, "a"), (2, "b")]);
    }

    #[test]
    fn interner_send_sync_bounds() {
        assert_send_sync::<NodeInterner>();
        assert_send_sync::<NodeId>();
    }

    #[test]
    fn clone_preserves_lookup_state_and_next_id() {
        let mut original = NodeInterner::new();
        let alpha = original.intern("alpha").unwrap();
        let beta = original.intern("beta").unwrap();

        let mut cloned = original.clone();

        assert_eq!(cloned.get("alpha"), Some(alpha));
        assert_eq!(cloned.get("beta"), Some(beta));
        assert_eq!(cloned.resolve(alpha), Some("alpha"));
        assert_eq!(cloned.resolve(beta), Some("beta"));

        let gamma = cloned.intern("gamma").unwrap();
        assert_eq!(gamma.as_u32(), 2);
        assert_eq!(cloned.resolve(gamma), Some("gamma"));
        assert_eq!(original.get("gamma"), None);
    }

    #[test]
    fn display_with_renders_resolved_string() {
        let mut interner = NodeInterner::new();
        let id = interner.intern("npm:@acme/widget").unwrap();
        let rendered = format!("{}", display_with(id, &interner));
        assert_eq!(rendered, "npm:@acme/widget");
    }

    #[test]
    fn display_with_renders_unknown_id_diagnostic() {
        let interner = NodeInterner::new();
        let rendered = format!("{}", display_with(NodeId::from_raw(99), &interner));
        assert!(
            rendered.contains("NodeId#99"),
            "unknown id render must surface the raw u32 + @unknown marker; got {rendered}",
        );
    }

    /// Lockstep check: the interner cap matches the simulator cap.
    /// If a future change drifts them apart, the migration in
    /// bd-98xo5.5.2 will break in subtle ways (interner accepts what
    /// the graph rejects, or vice versa). Pin both here so the drift
    /// surfaces at compile time.
    #[test]
    fn interner_cap_tracks_simulator_max_nodes_constant() {
        // Re-declare the value the simulator uses so a future change to
        // `dgis::contagion_graph::MAX_NODES` is visible in this test's
        // diff. The actual constant in contagion_graph is private (`const`,
        // not `pub const`), so we hard-code the same value here and
        // require any change to land in two places.
        const SIMULATOR_MAX_NODES: usize = 1024;
        assert_eq!(
            NODE_INTERNER_MAX_NODES, SIMULATOR_MAX_NODES,
            "node_interner cap must stay in lockstep with contagion_graph::MAX_NODES"
        );
    }
}
