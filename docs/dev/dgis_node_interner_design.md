# DGIS NodeId u32 Interning — Design Note

> Skeleton for [bd-98xo5.5.1](https://github.com/Dicklesworthstone/franken_node).
> Parent: bd-98xo5.5 (DGIS NodeId u32 interning, perf round-2 finding).
> Migration of `dgis::contagion_graph` internals to `NodeId(u32)` lands
> in bd-98xo5.5.2 — **NOT in this design note**.

## Why intern node ids

`dgis::contagion_graph::NodeId` is currently `pub type NodeId = String`.
A profiling round-2 hotspot table flagged dependency-graph traversal
during contagion-simulator runs: each edge dereference walks a
`BTreeMap<String, _>` keyed by the full node-id string. With realistic
graphs in the 1–10k node range and edge density ≥ 4, that's tens of
millions of string comparisons per simulation. Interning the ids to
`u32` collapses each lookup to one `Copy` plus one fixed-width
comparison.

## API surface (skeleton — no behaviour yet)

```rust
// crates/franken-node/src/dgis/node_interner.rs

pub struct NodeId(u32);  // Copy + Eq + PartialEq + Ord + PartialOrd + Hash + Debug

pub struct NodeInterner {
    to_str: Vec<String>,           // index = NodeId, value = original string
    from_str: BTreeMap<String, u32>,
}

impl NodeInterner {
    pub fn new() -> Self;
    pub fn intern(&mut self, s: &str) -> Result<NodeId, InternError>;
    pub fn resolve(&self, id: NodeId) -> Option<&str>;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn iter(&self) -> impl Iterator<Item = (NodeId, &str)>;
}

pub enum InternError {
    CapacityExceeded { max: usize },
}
```

## Three design decisions (from the bead's spec)

### Decision 1 — Display strategy: **`display_with(&interner)` (option a)**

The bead's parent task offered two options:
- **(a)** A helper like `fn display_with<'a>(&self, interner: &'a NodeInterner) -> impl fmt::Display + 'a` that callers invoke explicitly. The `NodeId` type itself stays `Copy + 'static`.
- **(b)** Carry a borrowed `&str` reference inside `NodeId` itself, so `Display` works without ceremony.

**Picking (a).** Three reasons:

1. **`Copy + 'static` is load-bearing for the simulator.** Today the simulator passes `NodeId` (currently `String`, soon `u32`) by value through breadth-first / depth-first queues that store `Vec<NodeId>`. If `NodeId` carries a borrow, the queue would need a lifetime annotation and downstream callers would need to thread that lifetime through every signature. The cost of decision (b) propagates everywhere; the cost of decision (a) is localised at format-call sites.
2. **No accidental Display on raw IDs.** Forgetting to look up the string for a `NodeId` is a feature: it forces every render site to acknowledge the interner is the source of truth. A bare `Display` impl on `NodeId(u32)` would render the integer (cryptic for logs); a `Display` impl that reaches for a global interner would either need thread-local state (fragile) or `unsafe`.
3. **Operator-facing output paths can be audited.** With (a), `rg "display_with" crates/franken-node/src/dgis/` enumerates every render site. The migration in bd-98xo5.5.2 can sweep these explicitly without missing call sites.

A debug-only `impl Debug for NodeId` rendering the bare u32 is fine — Debug is for developer eyeballs, not operator UI.

### Decision 2 — Determinism: **intern order is part of the simulation contract**

The simulator's determinism contract (per `contagion_graph.rs:9-11`) is
"identical `seed` + parameters produces a byte-identical graph". The
interner makes intern-order load-bearing for this contract:

- Each `intern(s)` call assigns the next free `u32`.
- `from_str` is a `BTreeMap`, so iteration order is by string key
  (stable across runs).
- `to_str` is a `Vec`, so iteration order is by insertion (which
  equals u32 order).

The simulator's existing entry points (`add_node`, `add_edge`,
`generate_deterministic`) drive `intern` in a fixed order determined by
their inputs. Therefore:

- For the migration (bd-98xo5.5.2), the audit step is to confirm that
  every `add_node` / `add_edge` call site reaches `intern` in the same
  order it would have computed `String::clone` today. The order is the
  invariant; the storage representation is the optimisation.
- `iter()` will return `(NodeId, &str)` pairs in **u32 order** (so
  `Vec` index order — i.e. insertion order). This is the natural
  ordering for the simulator's deterministic walks.
- A `iter_by_str()` variant returning `BTreeMap` order is intentionally
  NOT in the skeleton — adding it later is a one-liner if a use case
  emerges, and offering it now would silently let a caller pick the
  wrong order.

### Decision 3 — Capacity bound: **`MAX_NODES = 1024` (lifted from `contagion_graph::MAX_NODES`)**

The existing simulator caps a single graph at 1024 distinct nodes (per
`contagion_graph.rs:175`). The interner needs to match: a single graph
build session cannot exceed that count, so the interner cannot either.

- `intern` returns `Err(InternError::CapacityExceeded { max: MAX_NODES })`
  on the (MAX_NODES + 1)th distinct insert.
- Repeated inserts of an already-interned string are O(log N) via the
  `BTreeMap` lookup and never count against the cap.
- The cap is `pub const NODE_INTERNER_MAX_NODES: usize = 1024;` in this
  module so a future migration can adjust if the simulator's MAX_NODES
  ever changes; we'll keep them in lockstep via a unit test that
  reads both constants.

The `push_bounded` pattern used elsewhere in the codebase isn't a
clean fit here — interning is conceptually "add or return existing",
not "push or evict oldest". Bounding via explicit `Err` on the cliff
mirrors the cuckoo-filter pattern (bd-98xo5.3) rather than the
event-log pattern.

## What this skeleton does NOT do

- **No migration**. `dgis::contagion_graph` still uses `pub type NodeId = String`. Migration is bd-98xo5.5.2.
- **No Display impl on `NodeId`**. See Decision 1.
- **No serde derives on `NodeId`**. Serialised graphs currently use the string form; the migration bead has to pick a serialisation strategy (intern the strings on parse, or keep strings on the wire and intern on load — both viable, decision deferred).
- **No proptest / fuzz harness yet**. The migration will add round-trip property tests once `intern` ↔ `resolve` is on a load-bearing path.

## Forward references

- bd-98xo5.5.2 — Migrate `dgis::contagion_graph` internals to u32 NodeId (consumes this skeleton).
- bd-98xo5.5.5 — Measure production graph-traversal frequency to validate the optimisation effort (validates the round-2 hotspot signal that triggered this work).
