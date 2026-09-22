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
for pins or explicit workspace intent, not execution readiness. Direct inspection
does not evaluate conditional exports; the target queries below do. Actual
module-file loading and native runtime parity remain outside this command.
A graph hash is content identity, not authentication;
`--expected-hash` must come from an independently trusted source. No receipt or
security approval is fabricated, and `franken-node run` is unchanged.

## Executed tests

```sh
cargo test --manifest-path tools/module-graph/Cargo.toml \
  --bin franken-module-graph --test cli --test topology --test package_targets --test module_files --test source_graph
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

## Select conditional exports and internal imports

Select a target from one captured package manifest using the native ordered
package-map evaluator:

```sh
franken-module-graph ./project --resolve-export .
franken-module-graph ./project --resolve-export ./feature \
  --package-manifest node_modules/example/package.json \
  --condition node --condition require
franken-module-graph ./project --resolve-import '#local' \
  --package-manifest packages/api/package.json
```

`--condition` supplies the **complete** active condition set, not additions to
ambient runtime configuration. With no flags, the set is `node, import`.
`default` is always eligible at its source position. Specify `node-addons`,
`module-sync`, or custom conditions explicitly when they belong to the desired
runtime context. Condition-object insertion order is preserved even when other
Rust consumers compile serde_json without its preserve-order feature.

Selection handles main-export shorthand, explicit subpaths, exact-key precedence,
single-star patterns with longest-prefix/longest-key precedence, nested condition
fallback, null exclusions, and ordered array fallback. Invalid array targets may
be skipped, but an invalid configuration is not a fallback. A valid target whose
file is missing is still selected: the selector never searches later array entries
based on file existence. Reports include the matched key and successful condition
and array-index branch, including a distinct `external_package` target kind for
an imports mapping that still needs dependency lookup.

These queries have scope `package-map-target-selection`. `SELECTED` exits 0;
blocked, absent or unmatched mappings return `UNRESOLVED` and exit 1; malformed
metadata, unsafe targets and resource-limit violations return `ERROR` and exit 2.
No absent exports map is silently converted to a legacy `main`/index lookup.
Stable error codes distinguish blocked exports, undefined imports, invalid targets,
invalid configurations and invalid requests. Duplicate JSON keys are deliberately
rejected rather than following Node's last-key-wins parsing; backslashes, encoded
path separators, NUL and traversal segments are also refused. This stricter
admission boundary is not a claim of complete loader equivalence.

`--package-manifest` is an exact canonical project-relative `package.json` path,
not a package name, glob or importer-based search. Capture uses Unix directory
file descriptors and no-follow opening at every component. Symlinked manifests,
symlinked parent directories and nonregular files are rejected; a FIFO cannot
block the final open. Manifest bytes are bounded to 512 KiB and checked for ordinary
in-place mutation during reading. The evaluator uses those captured bytes once,
not a second pathname read. This does not promise an atomic snapshot of a hostile
filesystem or authenticate the selected package.

The `input_hash` binds the **exact manifest bytes**, including order and whitespace,
with a separate domain. Requiring that value rejects changed metadata before target
selection:

```sh
franken-module-graph ./project --resolve-export . \
  --expected-hash "$REVIEWED_PACKAGE_MAP_INPUT_HASH"
```

The old graph or topology hash cannot approve a target query. Conditions and the
requested subpath are explicit query inputs, not part of this manifest-only pin.
Target-query flags cannot be mixed with dependency/topology queries or
`--require-resolved`; they do not imply dependency closure completeness.

The module follows the package-map boundary in Node's published ESM resolution
specification, with public `require.resolve` and `import.meta.resolve` differential
fixtures. **Selection is not file resolution or permission to execute.** Local
results retain their package-relative URL spelling; external results retain a
package request. Existence, URL finalization, realpath, module format, full package
lookup, engine integration, policy admission and actual loading remain separate.
`filesystem_verified`, `execution_performed` and `release_certification` remain
false. No project lifecycle script or selected JavaScript module is executed.

## Resolve an importer to a captured module file

Resolve a concrete request from an existing project-relative importing file:

```sh
franken-module-graph ./project --resolve-module example/feature \
  --from packages/api/app.mjs --resolution-mode import
franken-module-graph ./project --resolve-module ./helpers \
  --from packages/api/app.cjs --resolution-mode require
franken-module-graph ./project --resolve-module '#internal' --from src/app.mjs
```

The production `supply_chain::module_resolution_graph::file_resolution` API now
composes ordered package maps with real importer-relative package search and
ordinary-file capture. It supports nearest nested, hoisted, scoped and aliased
packages; self references; internal imports including external-package targets;
CommonJS file-extension/main/index lookup; and strict ESM relative/subpath lookup.
ESM package roots without exports use legacy main/index resolution. Modern maps
remain encapsulation boundaries: blocked exports and selected-but-missing targets
never fall through to a package's main, inferred extension, later array target,
or a different installed version.

Resolution defaults to `import`. Conditions default to `node` plus the selected
mode; explicit `--condition` flags replace the complete set. ESM path percent
encoding is decoded, while query/fragment suffixes remain separate module-identity
evidence. CommonJS direct paths retain literal filename spelling. Resolution does
not load any JavaScript, parse its syntax, invoke hooks, install dependencies,
read `NODE_PATH`, or search outside the selected project. This is not the engine's
module loader and does not change `franken-node run`.

Successful output has scope `project-contained-module-resolution`, verdict
`RESOLVED`, exit 0, and a `resolution` object with the captured path, byte count,
SHA-256, format hint, package-map branches, and sorted positive/negative probes.
`filesystem_verified: true` means the returned file bytes were captured, not
that its package matches a lockfile or has passed trust admission. Unmarked
JavaScript reports `javascript_unspecified`; engine syntax detection is still
required. Native addons, Wasm and unknown extensions are only format hints, not
claims that execution is supported. Bare Node 22 core names and all `node:`
requests return `RUNTIME_REQUIRED`, exit 1, rather than allowing project packages
to shadow a runtime module. The engine's registry must establish availability
and capability authority independently.

The API returns a `CapturedResolution` with `source_bytes()`: consumers can use
the exact captured bytes rather than reopen a subsequently mutable pathname.
Source bytes are never serialized by this command. Only consulted files and
lookup gaps are captured; unused files and unrelated lockfile metadata are not
evidence. Directory descriptors remain owned throughout capture, and both
positive and negative probes are cached. Symlinks are rejected by default;
the explicit contained-link mode is described below. Nonregular files, path
escapes, reserved repository state, changed reads and exceeded bounds fail closed.
The supplied project root is trusted; this is not an atomic tree snapshot or
containment against a hostile filesystem. Input bounds are 1,024 probes, 64 path
components/recursive package transitions, 16 MiB per source file, 512 KiB per
manifest and 32 MiB total retained file bytes. It is not a real-time I/O deadline.

Pin the complete resolution context and evidence, not just its manifest:

```sh
franken-module-graph ./project --resolve-module example/feature \
  --from packages/api/app.mjs --expected-hash "$REVIEWED_RESOLUTION_HASH"
```

This separate domain-separated `input_hash` binds importer bytes, request, mode,
conditions, consulted manifests/source bytes, lookup gaps and selected result.
Moving identical inputs to a different root does not change it. A changed source
or newly introduced nearer candidate does. The command must capture and resolve
to compute this hash; a mismatch then returns `HASH_MISMATCH`, exit 1, with no
successful `resolution` payload. No execution occurs before or after the check.
Older graph, topology and manifest-only hashes cannot approve this scope.
Pins are consistency checks, not signatures or policy approvals.

Missing files, blocked mappings and unsupported directory imports return
`UNRESOLVED`, exit 1. Malformed inputs and unsafe capture return `ERROR`, exit 2.
All failure paths refuse successful file evidence. File resolution flags cannot
be combined with direct, topology or package-map-only queries. `--from` is an
existing module file, not the older manifest-oriented `--importer` option.

Unit and executable tests compare supported selections with Node's public
`require.resolve` and `import.meta.resolve`, without loading the selected source.
The latter deliberately permits missing file URLs; this resolver additionally
requires ordinary-file existence. Tests also exercise unchanged captured bytes,
hash/context drift, package encapsulation, aliases, root boundaries and FIFO/link
refusal. These tests do not establish full Node/Bun or engine loader parity.

### Workspace and pnpm-style package links

Opt in to project-contained symlinks when resolving an installed workspace or
a dependency in a pnpm-style virtual store:

```sh
franken-module-graph ./project --resolve-module workspace-package \
  --from src/app.mjs --allow-contained-symlinks
franken-module-graph ./project --resolve-module dependency \
  --from node_modules/workspace-package/main.cjs --resolution-mode require \
  --allow-contained-symlinks
```

This mode follows **relative links whose entire traversal stays inside the
selected project**. It captures link text with a bounded descriptor-relative
read and checks metadata before and after that read. Link components are then
expanded against retained directory descriptors; kernel opens still use
no-follow flags. Absolute link targets (even ones currently pointing inside the
project), outside-root targets, reserved repository state and nonregular targets
remain errors. Symlink cycles or more than 40 hops per lookup fail closed, as do
path/expansion/capture limits. Missing targets remain unresolved. The option is
available for `--resolve-module` and `--capture-source-graph`; it does not change
lockfile topology capture or standalone package-manifest inspection.

The importing file is finalized to its physical location **before** dependency
lookup, matching ordinary loaded-module context rather than lexical
`createRequire(alias)` or Node's preserve-symlinks modes. Package scope, self
references and subsequent dependency lookup therefore use the workspace or
virtual-store location, not the `node_modules` alias. The final source path and
format hint also use the physical file; ESM query/fragment identity is preserved.
Export encapsulation, condition selection and no-fallback behavior are unchanged.

Resolution reports and their hash domain are now v2. `importer` retains the
operator's input; `resolved_importer` records its physical location, and
`symlink_policy` records `reject` or `contained`. A `symlink` probe includes the
exact `link_target`, its byte count and SHA-256. The input pin binds these facts
alongside source bytes and all other consulted inputs. Changing a link's spelling
or the policy invalidates a reviewed pin even when the selected file bytes are
identical. Relative-link projects remain relocation-stable. Prior v1 resolution
hashes must be reviewed again; there is no silent legacy-hash acceptance.

Library callers use `resolve_with_policy(..., SymlinkPolicy::Contained)`;
`resolve(...)` retains strict rejection. Captured link text, missing probes and
source bytes are not reopened after capture. This is still not an atomic snapshot
of a hostile filesystem, lockfile verification, runtime permission, or execution
loader integration. The selected root is trusted and every allowed link must
remain within it; external development workspaces are deliberately unsupported.

## Capture an entrypoint's source dependency graph

Capture the supported static and literal dependency requests reachable from an
entrypoint, rather than resolving just one request:

```sh
franken-module-graph ./project --capture-source-graph src/app.mjs
franken-module-graph ./project --capture-source-graph src/app.cjs \
  --allow-contained-symlinks --expected-hash "$REVIEWED_SOURCE_GRAPH_HASH"
```

This uses the production
`module_resolution_graph::file_resolution::source_graph::capture` API. It
extracts JavaScript static imports and re-export sources, direct literal
`require` / `module.require` calls, and literal dynamic imports. Import edges use
`node, import`; require edges use `node, require`. Explicit `--condition` flags
replace the complete set for every edge. Supported quoted escapes and
substitution-free template literals are decoded without running JavaScript.
Comments and ordinary string contents are not treated as module requests.

Each edge records its source byte span, one-based line/column, load kind, request,
resolution status, target identity and selected package-map branches. Literal
calls are conservatively included even inside deferred functions or dead
branches: this is not a control-flow trace. Cycles and diamonds visit each
physical file plus ESM query/fragment identity once. Contained workspace links
retain physical package context. JSON modules are parsed as data, not scanned as
JavaScript. TypeScript and TSX use their own grammars and the explicit erasure
contract below. Native addons, Wasm and unknown source formats require separate
analysis and produce explicit diagnostics.

One resolver owns the entire graph capture. Sources, manifests, link text and
negative probes are cached once across all edges, not captured independently
from mutable paths. The `CapturedModuleGraph` owner provides a read-only report
and `source_bytes(&ModuleId)` so a future consumer need not reopen a pathname.
The command does not serialize source bytes or ordinary source literals. Module
requests, filenames, mappings and diagnostics are still potentially sensitive.

`CAPTURED` exits 0 only when this scanner's supported static/literal scope has no
unresolved sites or analysis diagnostics. `INCOMPLETE` exits 1 while retaining
good edges alongside missing imports, runtime-required builtins, nonliteral
loads, parse failures and observed indirect loader/code-generation surfaces.
Missing entrypoints return `UNRESOLVED`, exit 1. Unsafe capture and resource
failures return `ERROR`, exit 2, without a partial successful graph.

`fully_resolved` is **not runtime completeness**. Arbitrary aliases, computed
property access, generated code, binding/control-flow analysis, import-attribute
validation and module evaluation/linking semantics are outside the scanner.
Shadowed direct require calls can be conservative false positives. A tree-sitter
parse is not an engine compatibility result. `runtime_completeness`,
`execution_performed` and `release_certification` remain false on every result;
`franken-node run` and the engine loader are unchanged.

The domain-separated graph `input_hash` binds the entrypoint, conditions and
symlink policy, all captured source identities, edges, diagnostics, consulted
manifests and lookup gaps. Identical captures are relocation-stable. Changing a
transitive source or introducing a nearer resolution candidate changes the pin.
An `--expected-hash` mismatch exits 1 and suppresses the `source_graph` payload;
metadata-only, single-file and manifest-only pins cannot approve this scope.
Pins are consistency checks, not signatures, provenance or permission to execute.

Capture is bounded to 256 module identities, 4,096 dependency/diagnostic sites,
262,144 traversed syntax nodes and 32 MiB of report evidence, in addition to the
shared resolver's file/probe/link limits. There is no truncation-as-success and
no claim of a real-time I/O or parsing deadline. Neither this graph nor the
underlying observed capture is an atomic snapshot of a hostile filesystem.

Graph capture is mutually exclusive with the other query modes and with
`--from`, `--resolution-mode` and `--require-resolved`. Its own entrypoint and
per-edge load kinds establish the resolution contexts, and its result always
reports incomplete evidence without an additional strictness flag.

### TypeScript runtime dependencies and erased references

The same command accepts `.ts`, `.mts`, `.cts` and `.tsx` entrypoints and follows
mixed JavaScript/TypeScript graphs without executing or transpiling them:

```sh
franken-module-graph ./project --capture-source-graph src/app.ts
franken-module-graph ./project --capture-source-graph src/view.tsx \
  --allow-contained-symlinks
```

Each module records `source_language`, independently of the file resolver's
runtime `format_hint`. Parser selection follows the captured physical filename;
TypeScript syntax is not silently accepted in JavaScript files. The parser is
not a type checker or a claim that the engine can execute the selected syntax.

This analysis follows **explicit runtime syntax**, not a guessed `tsconfig`
emit strategy. Whole-declaration `import type` / `export type` references,
`import()` in type positions, and references in ambient declarations are retained
as `type_only` edges. They have no runtime conditions, target, or filesystem
lookup. Missing type packages, declaration files, symlinks and even outside-root
type specifiers do not grant the scanner authority to open those paths.
`type_resolution_performed` remains false. A valid erased edge does not make the
runtime-syntax capture incomplete; it does not certify type availability either.

Inline type specifiers have different semantics: `import { type T } from './x'`
and `export { type T } from './x'` retain the side-effect dependency on `./x`.
A default binding named `type` is also a value import. No use-based elision,
compiler option, implicit extension substitution, or `paths` alias is inferred.
Unmarked imports used only as types remain conservative runtime edges. All
erased sites still count against the global syntax and site limits.

Literal calls through transparent assertions/non-null wrappers, such as
`(require as Loader)('./dep.cjs')` and `require!('./dep.cjs')`, are followed using
require conditions. The erased operand's import types remain separate type-only
edges. Arbitrary stored aliases, sequence/conditional expressions, computed
requests and generated code still require additional analysis; wrappers are not
used to guess their targets.

`import X = require('pkg')` preserves its explicit require dependency but emits
`TYPESCRIPT_TRANSFORM_REQUIRED`. So do non-ambient enums/namespaces, parameter
properties, decorators, export assignments and angle-bracket assertions. JSX
keeps explicit dependencies and reports its existing unsupported-surface
diagnostic; no configured JSX-runtime or helper import is invented. These cases
return `INCOMPLETE` while retaining their explicit edges. Declaration files
(`.d.ts`, `.d.mts`, `.d.cts`) selected as runtime sources are not accepted as empty
implementations. Syntax failures retain source identity without claiming analysis.

The graph schema/hash domain is v2, binding language classification, erased-edge
decisions, source spellings and all runtime evidence. v1 pins must be reviewed
again. Changing an unread type dependency does not change this runtime-syntax
pin; changing its reference in captured source does. This remains neither a type
dependency graph nor a complete emitted-program or runtime execution graph.

Regression tests compare the runtime-edge subset against JavaScript produced by
Node's public `module.stripTypeScriptTypes` API, and resolve supported edges with
Node's public resolvers. Neither the fixture text nor the stripped output is
executed. The erasure contract follows TypeScript's `verbatimModuleSyntax`
documentation; it does not claim support for all valid TypeScript, bundler
resolution, Node's TypeScript execution restrictions, or engine integration.

## Retain and replay source-graph capsules

Save the observed inputs alongside an entrypoint-wide capture:

```sh
franken-module-graph ./project --capture-source-graph src/app.ts \
  --write-source-capsule /trusted/evidence/app.fnsc
```

The destination must be a **new file in an existing trusted directory**. Capsule
publication stages complete bytes, flushes and syncs them, then publishes without
overwriting an existing file, directory or symlink. The resulting file has mode
`0600`; source and manifest contents can contain credentials and private code.
Protect the artifact as source material, not merely as a public JSON report.
No source bytes are printed to stdout. The usual report gains `capsule_hash`,
`capsule_bytes` and `capsule_path` only after publication succeeds.

An optional `--expected-hash` on this capture command still means the reviewed
**source-graph input hash**. A mismatch prevents capsule publication. Captures
with unresolved imports or analysis diagnostics can be retained too, but the
command still returns `INCOMPLETE` and exit 1. A storage/publication failure
returns `ERROR`, exit 2, not a successful capture report. Directory changes by a
hostile actor or a crash during filesystem publication are outside the trusted
destination assumption; an unsuccessful command is not a publication receipt.

Replay elsewhere, without the original project or any live query options:

```sh
franken-module-graph --replay-source-capsule /trusted/evidence/app.fnsc \
  --expected-hash "$REVIEWED_CAPSULE_HASH"
```

Here `--expected-hash` is the independently obtained **capsule hash**, not its
source-graph hash or a hash taken from an untrusted artifact's own metadata. It
is mandatory and checked before decoding the capsule header. The domains are
distinct: a graph, manifest or single-resolution pin cannot approve capsule
bytes. A content pin establishes consistency with the reviewed bytes, not
producer authentication, trust, vulnerability status or permission to execute.

### Recompute from sealed observations, not from today's checkout

Replay uses the same production source parser and file resolver as capture. It
reconstructs an in-memory observation map containing captured source and manifest
bytes, directory facts, relative symlink text and absent-path observations. It
does **not** deserialize a saved graph and simply trust its success fields.
No original root path is accepted, no project files are opened, no package is
installed and no JavaScript is evaluated. Capsule paths are never extracted to
the filesystem. An observation omitted from the capsule is an error, never
silently interpreted as absent or filled in from the current machine.

The recomputed graph hash must equal the captured hash, and every retained
observation must be consulted. Altered payload digests, invalid paths or parent
relationships, duplicate/unused observations, unsupported schemas and truncated
or trailing payload bytes fail closed. Source identity, missing imports,
runtime-required builtins, TypeScript type-only edges, URL instances and all
analysis diagnostics are recomputed. Adding a formerly missing file on the
replay host cannot upgrade an incomplete result.

Successful verification reports `scope: "captured-source-graph-replay"` and
`replay_verified: true`. A fully resolved supported graph returns `REPLAYED`,
exit 0; a correctly reproduced incomplete graph returns `INCOMPLETE`, exit 1.
A capsule-pin mismatch returns `HASH_MISMATCH`, exit 1; malformed input or a
recomputation mismatch returns `ERROR`, exit 2. Rejected input has no successful
`source_graph` payload. `filesystem_verified`, `runtime_completeness`,
`execution_performed` and `release_certification` remain false in replay output.
The graph report itself retains its original scope and input hash.

### Portable format and limits

Capsules use the eight-byte magic `FNSGCAP1`, a four-byte little-endian header
length, canonical JSON metadata, and exact binary file payloads in sorted
physical-path order. Files are stored once even when multiple URL module
identities share them. The capsule identity is SHA-256 over the domain
`franken-node/module-source-capsule/v1` followed by a NUL byte, the eight-byte
little-endian encoded capsule length, and the complete capsule bytes. The
output spelling is `sha256:` followed by lowercase hexadecimal digits.

Headers are bounded to 8 MiB, retained file/link bytes to 32 MiB, inputs to 1,024,
ordinary files to 16 MiB and manifests to 512 KiB. The total encoded bound is
40 MiB plus 12 bytes. No archive decompression or filesystem materialization is
performed. All existing graph syntax/module/site budgets apply during replay.
The CLI additionally refuses nonregular, oversized or final-symlink capsule
inputs and detects ordinary mutation while reading; FIFOs cannot block admission.

The library APIs are `source_graph::capsule::encode(&captured)` and
`source_graph::capsule::replay(bytes, independent_pin)`. Replay returns the same
read-only `CapturedModuleGraph` owner and exact retained `source_bytes` as live
capture, without live directory handles. Re-encoding a replay is byte-identical.
This is replay of the supported **dependency analysis**, not execution, ambient
effects, a type-checking environment, or a hostile filesystem's atomic state.
Parser/resolver changes that alter the reconstructed graph are reported as a
replay mismatch rather than silently accepted. This build exposes the graph
analysis and capsule API on Unix; the encoded artifact itself has no host paths.
