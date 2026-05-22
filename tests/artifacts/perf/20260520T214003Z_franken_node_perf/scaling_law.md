# Scaling law — `20260520T214003Z_franken_node_perf`

The franken_node Criterion suite gives us **three orthogonal scale axes**.
Each axis tells a different story.

## Axis 1 — `trust_card_canonical` over JSON depth × width

Hot path: `canonicalize_value_current` (recursive `Value::clone()`).

| Card size      | Depth | Width | Leaf count | `current` p95     | `current` / per-leaf | `optimized` p95   | `optimized` / per-leaf |
|----------------|------:|------:|-----------:|------------------:|---------------------:|------------------:|------------------------:|
| `simple_1x5`   |     1 |     5 |     5      | 79.81 µs          | 15.96 µs             | 79.19 µs          | 15.84 µs                |
| `medium_3x8`   |     3 |     8 |   584      | 33.23 ms          | 56.90 µs             | 31.21 ms          | 53.44 µs                |
| `complex_4x12` |     4 |    12 | 22 620     | **3 591 ms**      | **158.74 µs**        | 3 437 ms          | 151.94 µs               |

**Verdict:** Super-linear in leaf count and roughly Θ(W^N × N) overall.
Per-leaf cost rises 9.9× (simple→medium) and 2.8× (medium→complex)
because the recursive `val.clone()` cost grows with the size of each
subtree, not just the count of leaves. The "optimized" variant trims
~4-6 % (the BTreeSet → Vec+sort win) but the *shape* of the curve
doesn't change — confirming that the bottleneck is the deep clone, not
the key ordering.

**Implication:** Real-world trust cards are flat (per the README
schema), so `simple_1x5` is the relevant data point — 80 µs is fine.
But any code path that produces deeper canonical JSON (incident
bundles, replay traces, federation payloads) inherits this O(W^N × N)
cliff. Treat `complex_4x12` as the **stress-test ceiling**, not the
production target.

## Axis 2 — `cuckoo_revocation` over filter cardinality (N)

Two operations with opposing scaling.

### Lookup (best-case scenario for cuckoo)

| N         | cuckoo p95 | BTree p95 | cuckoo/BTree |
|-----------|-----------:|----------:|-------------:|
|   1 000   | 57.5 ns    | 61.1 ns   | 0.94× (cuckoo wins) |
|  10 000   | 54.9 ns    | 85.6 ns   | 0.64× (cuckoo wins) |
| 100 000   | 54.9 ns    | 138.4 ns  | 0.40× (cuckoo wins) |
| 500 000   | 55.0 ns    | 178.3 ns  | **0.31× (cuckoo wins by 3.2×)** |

Cuckoo is **O(1)** (flat ≈ 55 ns regardless of N); BTree is **O(log N)**
(61 → 178 ns over a 500× range). Cuckoo wins more as N grows.

### Insert (the hidden cost)

| N         | cuckoo p95 | BTree p95 | cuckoo/BTree |
|-----------|-----------:|----------:|-------------:|
|  10 000   | 1.667 ms   | 2.469 ms  | 0.68× (cuckoo wins) |
|  50 000   | **24.78 ms** | **13.47 ms** | **1.84× (BTree wins by ≈2×)** |

Cuckoo's insertion cost crosses BTree somewhere between N=10 k and
N=50 k — most likely as the load factor approaches the cuckoo eviction
cliff. Past that point, every insert can trigger a chain of evictions
proportional to the depth of the colliding bucket.

**Verdict:** Choice is **workload-shape-dependent**, not absolute.
For a revocation frontier with N > 30 k that grows during the run,
BTree is the safer choice. For a static frontier with bursty lookups,
cuckoo dominates.

## Axis 3 — `replay_bundle_generation` over event count

Pure linear scaling, no algorithmic cliffs.

| Events   | p95         | per-event |
|---------:|------------:|----------:|
|     10   | 323.4 µs    | 32.3 µs   |
|    100   | 2.937 ms    | 29.4 µs   |
|   1 000  | 29.47 ms    | 29.5 µs   |

**Verdict:** Linear amortised throughput at ~29 µs / event.
**No algorithmic optimisation lever here** — costs scale exactly with
input size. The room to optimise is per-event constant-factor work
(e.g. allocator churn inside event serialisation), not algorithm.

## Axis 4 — `threshold_sig_verify` over signer count

| Signers | `current` p95 | `preparsed_keys` p95 | preparsed / current |
|--------:|--------------:|---------------------:|--------------------:|
|       8 | 433.6 µs      | 396.4 µs             | 0.913× |
|      32 | 1 778 µs      | 1 611 µs             | 0.906× |

| Pair   | current        | preparsed      |
|--------|---------------:|---------------:|
| 32/8   | 4.10×          | 4.06×          |

**Verdict:** **Sub-linear in signer count** (4× signers ⇒ 4.1× time,
not 4.5× or worse). The preparsed-keys path saves a flat ~9 % at every
N — meaning the dominant cost is the Ed25519 verify itself, not the
hex-decode + VerifyingKey parse. There is **no algorithmic lever** at
the user-code level beyond what `verify_batch` (dalek's batched
verification) offers — but that requires API change.

## Axis 5 — `crypto::Ed25519Scheme` over payload size

| Payload bytes | `dalek_direct` sign | `scheme.sign_raw` | scheme / direct | scheme delta |
|--------------:|--------------------:|------------------:|----------------:|-------------:|
|            64 | 23.86 µs            | 45.69 µs          | **1.91×**       | +21.83 µs    |
|           512 | 26.68 µs            | 47.30 µs          | 1.77×           | +20.62 µs    |
|          4096 | 41.70 µs            | 63.60 µs          | 1.52×           | +21.90 µs    |

| Payload bytes | `dalek_direct` verify | `scheme.verify_raw` | scheme / direct | scheme delta |
|--------------:|----------------------:|--------------------:|----------------:|-------------:|
|            64 | 47.25 µs              | 53.30 µs            | 1.13×           | +6.05 µs     |
|           512 | 48.28 µs              | 54.02 µs            | 1.12×           | +5.74 µs     |
|          4096 | 56.75 µs              | 62.62 µs            | 1.10×           | +5.87 µs     |

**Verdict:** The wrapper adds a **flat 22 µs / sign and 6 µs / verify**
regardless of payload size. That isolates the overhead to a one-time
cost per call — the `SigningKey::from_bytes(secret_key)` and
`VerifyingKey::from_bytes(public_key)` at
`crates/franken-node/src/crypto/schemes.rs:240,252`. Caching parsed
keys eliminates this overhead entirely.

## Cross-axis observation

The two **highest-leverage optimisation candidates** both have the
same root cause: **a per-call cost that should be a one-time cost**.

- Rank 1 (`trust_card_canonical`): `Value::clone()` of the entire
  subtree at every recursion level should be a sorted view + streamed
  write, no clone.
- Rank 2 (`Ed25519Scheme::sign_raw`): `SigningKey::from_bytes` rebuilt
  per sign should be cached or accepted pre-built.

Same root, different surface. The next skill should weigh whether to
attack both with the same lever (introduce a "preparsed handle"
pattern, mirroring `PreparsedThresholdConfig`) or separately.
