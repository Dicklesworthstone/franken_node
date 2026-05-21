# Canonical Encoder Audit — bd-98xo5.4.1

Inventory of the production canonical-JSON paths in franken_node ahead
of the T4 trust_card streaming-encoder rewrite (bd-98xo5.4 epic).
This audit answers the critical question: **is the bench's 3 591 ms
`current/complex_4x12` headline a fair reflection of what production
does today, or is it a bench-local artifact?**

TL;DR: the 3 591 ms figure is **partly a bench artifact**. The
`connector::canonical_serializer` is already a streaming, borrow-based
encoder — there is nothing to remove there. The
`supply_chain::trust_card::canonicalize_value` path IS the legitimate
T4 target, but it's a *move*-based tree-rebuild, not a *clone*-based
one. The bench's `canonicalize_value_current` variant uses `.clone()`
on every recursive descent (which production does NOT do), so the
expected real-world T4 win is smaller than the headline implies.

## 1. Functions in production that produce canonical bytes

| # | Function (file:line) | Input | Output | Strategy |
|---|----------------------|-------|--------|----------|
| 1 | [`connector::canonical_serializer::write_canonical_value`](../../crates/franken-node/src/connector/canonical_serializer.rs#L864) | `value: &Value` (borrowed) | bytes appended to `&mut Vec<u8>` | **streaming**: walks borrowed Value, emits bytes inline; uses `CanonicalFieldPath` stack-allocated borrowed-parent chain that renders to `String` ONLY on the error branch |
| 2 | [`connector::canonical_serializer::canonicalize_schema_value`](../../crates/franken-node/src/connector/canonical_serializer.rs#L762) | `value: &Value` + `RegisteredCanonicalSchema` | `Vec<u8>` | thin wrapper that emits `{` / `,` / `}` and field-name pairs, calling `write_canonical_value` for each field value. Honors a fixed `field_order` from the schema — no key sort needed |
| 3 | [`connector::canonical_serializer::CanonicalSerializer::serialize_value`](../../crates/franken-node/src/connector/canonical_serializer.rs#L476) | `value: &Value` | `Vec<u8>` | top-level entry point that resolves the schema by `TrustObjectType` and calls `canonicalize_schema_value` |
| 4 | [`supply_chain::trust_card::to_canonical_json`](../../crates/franken-node/src/supply_chain/trust_card.rs#L2764) | `value: &T: Serialize + ?Sized` | `String` | **tree-rebuild**: `serde_json::to_value(value) → canonicalize_value(raw) → serde_json::to_string(&canonical)`. Allocates one Value tree, rebuilds it with sorted keys, then serializes the rebuilt tree |
| 5 | [`supply_chain::trust_card::canonicalize_value`](../../crates/franken-node/src/supply_chain/trust_card.rs#L3274) | `value: Value` (by-value, moved) | `Value` | **tree-rebuild**: collects entries via `map.into_iter().collect::<Vec<_>>()`, sorts by key, inserts into a new `Map::with_capacity`, recurses on moved nested values. NO `Value::clone()` — but allocates the entries Vec + new Map + each recursive frame's intermediate Value |
| 6 | [`supply_chain::trust_card::compute_card_hash`](../../crates/franken-node/src/supply_chain/trust_card.rs#L2739) | `card: &TrustCard` | hex SHA-256 string | calls `canonical_card_without_hash_and_signature` (which calls `canonicalize_value`), then `serde_json::to_vec(&canonical)`, then SHA-256. Same tree-rebuild cost as #4 plus one Vec<u8> serialize |
| 7 | [`supply_chain::trust_card::canonical_card_without_hash_and_signature`](../../crates/franken-node/src/supply_chain/trust_card.rs#L2971) | `card: &TrustCard` | `Value` | helper: `serde_json::to_value(card) → blank out card_hash/registry_signature → canonicalize_value`. Same cost profile as #5 |
| 8 | [`supply_chain::trust_card::compute_snapshot_hash`](../../crates/franken-node/src/supply_chain/trust_card.rs#L3009) | `snapshot: &TrustCardRegistrySnapshot` | hex SHA-256 string | snapshot analog of #6 — also routes through `canonicalize_value` |

## 2. Which clone the input tree (vs operate on `&Value`)?

| Function | Clones tree? | Notes |
|----------|--------------|-------|
| `connector::canonical_serializer::write_canonical_value` | **No** | Operates on `&Value`. The only Vec it builds during the walk is `entries: Vec<_> = values.iter().collect()` for object key sorting (line 909), and that's a Vec of `(&String, &Value)` — references, not owned data |
| `connector::canonical_serializer::canonicalize_schema_value` | **No** | Borrowed input throughout; only the output `Vec<u8>` is allocated |
| `connector::canonical_serializer::CanonicalSerializer::serialize_value` | **No** | Delegates to the borrow-based encoder above |
| `supply_chain::trust_card::canonicalize_value` | **Moves, doesn't clone** | Takes `Value` by value (caller's tree is consumed). `map.into_iter()` moves entries. NO `Value::clone()` calls. But rebuilds a new tree, so the allocation cost is: one entries Vec per object + one new Map per object + one new Vec<Value> per array + recursive intermediate Values |
| `supply_chain::trust_card::to_canonical_json` | **Allocates one Value tree first** | `serde_json::to_value(value)` produces a fully-owned Value tree from the serializable input. Then `canonicalize_value` consumes-and-rebuilds it. So end-to-end: 1 to_value tree + 1 tree-rebuild + 1 to_string |
| `supply_chain::trust_card::compute_card_hash` | **Same as #4** | Plus one extra `to_vec` for the SHA-256 input |

**Comparison with the bench:**

The bench at
[`crates/franken-node/benches/trust_card_canonical_bench.rs:17`](../../crates/franken-node/benches/trust_card_canonical_bench.rs#L17)
defines `canonicalize_value_current` which clones aggressively:

```rust
fn canonicalize_value_current(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: BTreeSet<String> = BTreeSet::new();
            for key in map.keys() {
                keys.insert(key.clone());           // <-- clone every key
            }
            let mut out = serde_json::Map::new();
            for key in keys {
                if let Some(val) = map.get(&key) {
                    out.insert(key, canonicalize_value_current(val.clone()));  // <-- clone every value
                }
            }
            ...
```

That's `O(N)` extra clones on every object descent — once for keys
(via the BTreeSet) and once for each value (via `val.clone()` on the
recursive call). Production `supply_chain::trust_card::canonicalize_value`
does NEITHER: it consumes via `into_iter()` (no key clone, no value
clone). The bench's `current` variant is therefore measuring strictly
*more* work than production does today.

The bench's `canonicalize_value_optimized` (line 40) also clones
values on the recursive call (line 49 `val.clone()`), so it too is
measuring more work than production — though less than `current`.

The bench's THIRD family of variants (`write_value_current_like` at
line 193, `write_value_no_path_alloc` at line 238,
`write_value_direct_string` at line 281) IS borrow-based and emits
bytes directly. These mirror the structure of
`connector::canonical_serializer::write_canonical_value` — they're
the apples-to-apples comparison against production.

## 3. Is the existing `CanonicalSerializer` already a near-streaming encoder?

**Yes.** The connector::canonical_serializer surface is functionally
equivalent to the bench's `write_value_no_path_alloc` variant, with
two refinements:

- **Lazy field-path rendering**: `CanonicalFieldPath` (line 814) is a
  small enum that holds borrowed parent references; rendering to a
  `String` only happens when an error needs to report the path (via
  `field_path.render()` at line 883/890). The bench's `write_value_current_like`
  always allocates `format!("{field_path}[{index}]")` on every
  descent (line 214 / 229), which is the allocation hygiene gap
  production has already closed.
- **Pre-allocated output buffer**: `canonicalize_schema_value`
  (line 786) starts with `Vec::with_capacity(registered_schema.min_object_capacity)`,
  matching `estimate_canonical_object_capacity` at line 164.

So for any TrustObjectType that goes through `CanonicalSerializer`,
**there is nothing T4 should change**. The bench's `current` variant
is measuring an *intentionally-pessimal* implementation as a
comparison baseline — not what production does.

## 4. Implication for the bd-98xo5.4 epic

The 3 591 ms `current/complex_4x12` figure from round 1
(`tests/artifacts/perf/20260520T214003Z_franken_node_perf/criterion_raw/trust_card_canonical.txt`)
should be interpreted as **the cost of a deep-cloning, BTreeSet-collecting
encoder running on a complex_4x12 (4-deep × 12-wide) tree** — not as
"this is what trust_card actually pays per call."

The legitimate T4 target is the
`supply_chain::trust_card::canonicalize_value` rebuild pattern at
[`trust_card.rs:3274`](../../crates/franken-node/src/supply_chain/trust_card.rs#L3274)
plus its `to_canonical_json` / `compute_card_hash` / `compute_snapshot_hash`
call sites. Replacing the consume-and-rebuild pattern with a
direct-to-Vec<u8> streaming walk (modeled on
`canonical_serializer::write_canonical_value`) eliminates:

- the intermediate sorted-`Map` allocation per object
- the intermediate `Vec<(String, Value)>` from `into_iter().collect()` per object
- the intermediate `Vec<Value>` from `into_iter().collect()` per array
- the final `serde_json::to_string(&canonical)` step (the streaming
  walk goes directly to the same bytes)

But it does NOT eliminate `Value::clone()`, because production
doesn't have any to remove. The realistic T4 win is the allocation
hygiene gap between bench `canonicalize_value_optimized` and
`write_value_no_path_alloc`, NOT the full `current → optimized → streaming`
ladder.

## 5. Recommended T4.2 shape

Author one streaming encoder in `supply_chain/trust_card.rs` that:

1. Takes `value: &Value` (or any `&T: Serialize`).
2. Writes directly to `&mut Vec<u8>`.
3. Sorts object keys via `let entries: Vec<_> = map.iter().collect(); entries.sort_by_key(|(k,_)| *k)` (references, not clones).
4. Recurses on borrowed nested values.
5. Replaces the three call sites at `to_canonical_json`,
   `compute_card_hash`, and `compute_snapshot_hash` to use the new
   streaming encoder instead of `canonicalize_value`+`to_string`/`to_vec`.

After the rewrite, `canonicalize_value` (the tree-rebuild) becomes
dead code at production call sites; whether to remove it or keep it
behind a `#[cfg(test)]` gate is a follow-on decision.

## 6. Out of scope

- **No changes to `connector::canonical_serializer`** — it's already
  streaming. Any "deep-clone removal" framing applied there is a
  misread of the bench.
- **No changes to the `field_order`-driven schema path
  (`canonicalize_schema_value`)** — that's separate from trust_card's
  byte-key sort and serves different objects (PolicyCheckpoint, etc.).
- **No changes to bench code** — the deep-clone bench variants stay
  in place as comparison baselines; the T4.2 ship will add a new
  bench case that exercises the new streaming encoder against
  `canonicalize_value_current` and against `canonicalize_value_optimized`.

## 7. Tracking

- Parent epic: [`bd-98xo5`](../../.beads/issues.jsonl) (franken_node
  performance optimization).
- This audit: [`bd-98xo5.4.1`](../../.beads/issues.jsonl).
- Streaming-encoder implementation: [`bd-98xo5.4.2`](../../.beads/issues.jsonl)
  (forward-referenced; will consume this audit's recommendations).
- Parent task: [`bd-98xo5.4`](../../.beads/issues.jsonl) — T4
  trust_card canonical encoder structural deep-clone removal (score 6.3).
