# Native package graph inspection

`franken-module-graph` runs the product's actual Rust module-graph builder without
linking the optional sibling execution engine. It reads root/workspace manifests
and npm `package-lock.json`, emits deterministic graph evidence, and supports
importer-specific dependency queries and independently pinned hash checks. It
never installs dependencies or executes project JavaScript or lifecycle scripts.

```sh
cargo run --manifest-path tools/module-graph/Cargo.toml -- /path/to/project
cargo run --manifest-path tools/module-graph/Cargo.toml -- /path/to/project \
  --importer packages/app/package.json --dependency '@scope/tool' --require-resolved
cargo run --manifest-path tools/module-graph/Cargo.toml -- /path/to/project \
  --expected-hash 'sha256:<64-lowercase-hex-digits>'
```

Exit 0 means inspection succeeded and any requested checks passed; 1 means a
hash mismatch or a required-but-unresolved edge; 2 means invalid input or an I/O
error. Errors and reports are JSON. `--dependency` selects that manifest's
explicitly declared edges across dependency kinds. Without any query flags,
the complete graph is exported. `--importer` defaults to `package.json` and must
exactly match a captured project-relative manifest path.

## Resolution contract

Each importer walks recorded `node_modules` locations from its own directory to
the project root. A root dependency cannot accidentally select a sibling's nested
version. Scoped names and installation aliases retain their installation path;
modern lockfiles can separately identify the alias target's real package name.
No location above the project, global package directory, or `NODE_PATH` is used.

Modern npm v2/v3 `packages` maps are authoritative; redundant legacy records are
not merged into them. npm v1's nested `dependencies` hierarchy is converted to
explicit installation paths, with `requires` retained separately from nested
installation records. Unknown lockfile versions and malformed locations, records,
requirements, or link metadata fail rather than silently producing an empty
successful graph. These are npm lockfile formats, not pnpm/yarn/Bun lock parsers.

An ordinary dependency range does not imply a same-named local workspace. A
recorded workspace link binds through its exact captured target directory.
Explicit `workspace:` requests can record workspace intent even without an
installed link; a null `lockfile_package_path` makes that distinction visible.
Duplicate workspace names and links to uncaptured workspaces fail closed.

## What the evidence does not establish

This is **lockfile-metadata inspection**, not a semver solver, installer, trust
verifier, or proof that live `node_modules` matches the lock. The selected version
is the nearest *recorded* installation, not an inferred preferred version. A
workspace intent is not proof of an installed link. In direct mode, `--require-resolved` checks
for pins or explicit workspace intent, not execution readiness. Conditional
exports evaluation, actual module-file loading and native runtime parity remain
outside this command. A graph hash is content identity, not authentication;
`--expected-hash` must come from an independently trusted source. No receipt or
security approval is fabricated, and `franken-node run` is unchanged.

## Executed tests

```sh
cargo test --manifest-path tools/module-graph/Cargo.toml \
  --bin franken-module-graph --test cli --test topology
```

The graph builder's own unit tests run alongside executable CLI regressions.
Node must be available for the resolver oracle: it compares real
`createRequire(...).resolve(...)` choices against the Rust graph for nested,
hoisted, scoped and alias installations. Fixture modules throw if evaluated, so
resolver comparison does not silently substitute successful program execution.
The schema registry is compiled from production source as a non-test dependency;
its full-workspace tests are not claimed by this focused command.

## Transitive requirements and reverse impact

Inspect the entire declared dependency closure of the root or an exact workspace
or lockfile package manifest location:

```sh
franken-module-graph ./project --transitive --require-resolved
franken-module-graph ./project --transitive --importer packages/api/package.json
franken-module-graph ./project --transitive --importer node_modules/server/package.json
```

Find which captured project/workspace manifests depend on **one exact package
instance**, directly or transitively:

```sh
franken-module-graph ./project --impact node_modules/server/node_modules/parser
```

This is useful for assessing the potential reach of a vulnerable, revoked or
changed package. Two versions installed under different paths remain different
nodes. The result is declared dependency reachability, **not a vulnerability
verdict, live module-use trace, or permission to quarantine/release anything**.
It performs no package installation, lifecycle script, project-code execution,
network access or live filesystem verification of installed package contents.

The existing command's `--dependency` mode and direct graph wire shape remain
available. `--transitive`, `--impact` and `--dependency` are mutually exclusive.
An impact target is an exact location (`.` for the root); it is not a package
name, version range, glob, filename, or normalized path. `--importer` is available
with dependency and transitive queries, not impact. For installed nodes, the
manifest location describes the lockfile record; no physical manifest need exist.

### What the topology represents

The production graph parser supplies both views from the same metadata read.
There is no second lockfile read after hashing the first. Installed requirements
use nearest recorded `node_modules` lookup from each importing package, including
nested, hoisted, scoped and aliased installation paths. A workspace link is an
explicit node transitioning to the real captured workspace. Its requirements
resolve from that workspace, not from the lexical link location.

Modern lockfile requirements include production, optional and peer dependencies.
Root/workspace manifests also contribute development dependencies; installed
packages' development requirements do not propagate into consumer closures.
Optional requirements override same-name production requirements. Optional peer
metadata is preserved. Version ranges are recorded, not solved or proven to
match the selected version. Package-manager overrides, platform installation
filters, conditional exports and actual runtime imports are not evaluated.

Results have `scope: "declared-dependency-topology"` and include the canonical
`topology` plus a `closure` or `impact` result. Edges preserve the declaration,
kind, optionality, exact target and selection source. Query edge-index arrays
refer to this accompanying topology. Locations, requirements and query outputs
are deterministic and sorted. A closure includes its starting package. Impact
includes the target and known reverse dependents; `affected_manifests` selects
the root/workspaces among them. `toward_target` is a shared deterministic
shortest-path witness: follow each location's `next` to reach the target. It does
not expand all possible paths through cycles or diamonds.

### Incomplete evidence stays visible

`fully_resolved` is true only when all requirements in the query's scope have
recorded targets, there is no uninstalled `workspace:` intent, and dependency
kind metadata is complete. This is resolution within recorded metadata, **never
proof of installation or trust**. Missing optional dependencies and optional
peers remain visible, with separate required/optional counts in closures. They
can be legitimate installation outcomes; they still prevent the strict
`--require-resolved` check from succeeding.

Legacy npm v1 `requires` can produce transitive paths but does not retain enough
modern kind metadata. Its installed edges have a null `dependency_kind`, and
queries touching them cannot claim `metadata_complete`. Workspace intent is
traversable, but remains separate from an installed lockfile link.

Impact completeness checks **all** recorded branches: an unresolved branch may
hide another route to the target. Consequently, an empty `affected_manifests`
with incomplete evidence must not be interpreted as proof that no workspace is
exposed. Closure completeness applies only to its reachable subgraph.

Without `--require-resolved`, inspection succeeds while reporting gaps. With the
flag, incomplete topology returns `UNRESOLVED` and exit 1. Unknown locations and
invalid metadata return `ERROR` and exit 2. A hash mismatch also exits 1 and takes
precedence over a resolution-gap verdict; neither case erases the query evidence.

### Pin the richer evidence, not its older projection

Transitive/impact output uses a separate domain-separated topology hash. Pass
its `canonical_hash` to `--expected-hash` when repeating either topology query:

```sh
franken-module-graph ./project --impact node_modules/parser \
  --expected-hash "${REVIEWED_TOPOLOGY_HASH}" --require-resolved
```

A direct graph hash cannot approve a topology query: the older projection does
not bind all installed optional/peer/link facts. `topology.source_graph_hash`
records that projection as provenance, while the topology hash binds the richer
nodes, edges and completeness metadata. Neither hash authenticates its producer
or replaces an independently trusted review. Both query modes share the same
full-topology hash, irrespective of selected start or impact target.

Construction bounds installed requirements globally to 65,536, total edges to
81,920, nodes to 16,640 and retained topology text to 32 MiB, in addition to the
existing manifest and lockfile limits. Queries use iterative, once-per-node
traversal and bounded shared witnesses. Budget violations return errors, not
truncated successful results.

The native module-graph tests compile these exact production modules. They cover
nested versions, cycles, missing branches, role/optional semantics, real workspace
locations, legacy uncertainty, hash changes and binary CLI behavior; a real Node
resolver checks transitive scoped/aliased/nested selections without loading the
package's deliberately throwing source. These checks do not establish full
Node/Bun module-loader equivalence.
