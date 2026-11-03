# Captured source delivery to FrankenEngine

`source_graph::engine_resolver::CapturedEngineResolver` implements the sibling
engine's actual `ModuleResolver` trait when the product's `engine` feature is
enabled. It connects a reviewed live capture or replayed source capsule to
engine-native `ModuleRecord`, `ResolvedModule`, hash and policy-hook types.
It does not reinterpret a pathname or re-run package lookup during a load.

```rust,ignore
use frankenengine_engine::{
    capability::RuntimeCapability,
    module_resolver::{CapabilityPolicyHook, ModuleResolver, ResolutionContext},
};
use frankenengine_node::supply_chain::module_resolution_graph::file_resolution::source_graph;
use source_graph::engine_resolver::CapturedEngineResolver;

let graph = source_graph::capsule::replay(&capsule_bytes, reviewed_capsule_hash)?;
let resolver = CapturedEngineResolver::new(graph, reviewed_graph_hash)?;
let context = ResolutionContext::new("trace-id", "decision-id", "policy-id");
let policy = CapabilityPolicyHook::new([RuntimeCapability::ModuleLoad].into());
let request = resolver.entry_request();
let source = resolver.resolve(&request, &context, &policy)?;
// Pass the source and dependency records to the engine's module machinery.
// A successful source lookup is not an evaluation result or an effect permit.
```

Both pins must come from independently reviewed inputs, not an untrusted
artifact's self-reported hash. The capsule pin authenticates byte consistency;
the graph pin identifies the exact analysis admitted to the source registry.
Neither pin identifies a publisher or grants capabilities.

## Required sibling revision

The native JSON foundation landed in `franken_engine` commit
[`eccb440d246089086106c02be5a0acea84147f4e`](https://github.com/Dicklesworthstone/franken_engine/commit/eccb440d246089086106c02be5a0acea84147f4e)
with `ModuleSyntax::Json` and the intrinsic JSON module loader. This bridge now
also requires the static-attribute contract: `import_attributes::ImportAttributes`,
attribute-bearing `ModuleRequest` and `ModuleDependency`, static import/reexport
transport, and the resolver's shared format-validation helpers. The earlier
JSON foundation commit alone is insufficient. The metadata contract includes
`ModuleMetadataTarget`, `ModuleResolver::resolve_metadata`,
`ModulePolicyHook::authorize_metadata` and native `import.meta.resolve`.
The Cargo path dependency on the
sibling checkout is intentional; it does not select or enforce a Git revision.
The CI checkout pins the sibling revision used to verify these APIs together.

## Closed-world behavior

Admission consumes the capture and builds immutable, `Send + Sync` source
storage. Sources sharing a physical path share their storage, while ESM URL
instances remain distinct identities. IDs are domain-separated, graph-scoped
opaque strings. Changing any graph input changes those IDs; a referrer from an
older capture cannot be reused with the new registry. They are not filesystem
paths or JavaScript URLs to parse or reopen.

Only the entrypoint's generated request is accepted without a referrer.
Subsequent requests must use the returned engine record ID as referrer and the
exact captured specifier, import/require style and load/filename/URL-lookup
purpose. Knowing a target's canonical ID does not create a new edge to it. Nested package versions, condition choices,
workspace links and missing lookup decisions are never reinterpreted using the
ambient machine. Unknown requests fail rather than falling back to another
resolver. Engine requests must use `NodeCompat`; the helper entry request does
this explicitly. These captured choices cannot be relabelled Native or Bun.

Captured require, require.resolve and dynamic import() absences remain terminal after later
installation or capsule replay. The engine throws `MODULE_NOT_FOUND` for require
and require.resolve, and rejects the import promise with `ERR_MODULE_NOT_FOUND`. Missing static
imports, invalid metadata, denied exports and unknown routes remain refusals.
Eager `resolve_chain` fails on any missing target.

Literal `require`, static `import`, reexport and dynamic `import()` routes can
deliver the engine's native `buffer`, `crypto`, `zlib`, `fs`, `fs/promises`,
`module`, `events`, `os`, `querystring`, `url`, `timers`, `timers/promises`,
`perf_hooks`, `path`, `path/posix`, `path/win32`, `util`, `util/types`, `assert`,
`assert/strict`, `string_decoder`, `stream`, `stream/promises`, `stream/consumers`,
`stream/web`, `readline`, `readline/promises` and `diagnostics_channel` providers,
including their `node:` spellings. The registry admits only names in the engine's
canonical provider inventory. These are source-free terminal descriptors, not
captured files; the capture report continues to identify them as runtime
requirements. Every load needs `ModuleLoad` and `Builtin`. `timers`,
`timers/promises`, `stream`, `stream/promises`, `readline`, `readline/promises`
and `diagnostics_channel` additionally need `Timer` for their existing timer,
next-tick or microtask behavior. Loading a provider does not grant filesystem,
network or process rights; optional effects still need their existing host
capabilities.

The engine owns evaluation and caches the CommonJS object and ESM namespace in
the execution realm. ESM exposes the provider's named exports and a `default`
equal to its CommonJS value. Bare and `node:` spellings share their namespace;
`path` and `path/posix` have distinct namespaces with the same POSIX default
object. Importing a cached provider still performs the current request's policy
and descriptor-integrity checks. The engine also checks the bounded-import
information-flow contract before exposing a namespace. Computed loads and
unsupported providers do not gain a fallback to host I/O.

The `util`, `assert` and `string_decoder` providers execute the engine's existing
module factories as retained native modules. Extracted methods and functions
exported by npm packages keep their defining module context. `util/types` shares
the parent's `types` object, and `assert/strict` shares the parent's `strict`
function. `readline` and `diagnostics_channel` also retain one factory per realm,
so importing packages share constructors, channel subscriptions and channel
identity. `readline/promises` retains the parent's original promises object even
if guest code later replaces the public property. Readline uses the same native
EventEmitter and string decoder as direct imports, including split UTF-8 input.
The diagnostics namespace admits only authenticated, deferred native
`hasSubscribers` getters; guest replacements and getters used to snapshot export
values still fail the bounded-import contract. No builtin implementation is
copied into the product or captured capsule; capsule replay uses the installed
engine's authenticated provider.

Only closed graphs with analyzed executable sources are admitted. Resolution-only
targets have no language or source-preparation requirement. The engine-independent
`PinnedModuleRegistry::new` remains transform-free and requires explicit
JavaScript ESM/CommonJS formats. The engine-backed constructor additionally
prepares the following captured sources using the real sibling front end:

- Unmarked `.js` and extensionless JavaScript: the engine parser tests a CommonJS
  function body first, then an ES module. This accounts for top-level return and
  lexical conflicts with CommonJS wrapper parameters without a second parser or
  a text-based import/export heuristic. The detection wrapper is never delivered.
- Exact dependencies with unrecognized extensions, such as `require('./tool.generated')`,
  use the same engine syntax detection when reached exclusively through `require`.
  This includes package `main` and `exports` targets and keeps CommonJS versus
  synchronous ESM selection independent of the enclosing package's `type`.
  Their nested dependencies, original filenames and per-load policy checks stay
  in the captured graph. No new extension probing is added. Unknown-extension
  entrypoints and any static import, reexport or dynamic import of these files
  remain outside admission, including mixed require/import graphs. Recognized
  JSON, TypeScript, native-addon and Wasm formats keep their separate rules;
  JSX syntax remains unsupported.
- Explicit `.mts` and `.cts`: the engine's public source-preparation function
  normalizes supported TypeScript, with ESM/CommonJS format fixed by extension.
  Plain `.ts` uses the package scope captured by the file resolver; an explicit
  unmarked-scope observation permits engine syntax detection. No live manifest
  read or implicit `.ts` extension/index search is added during preparation.
- JavaScript hashbangs: the same engine source-preparation function handles them.
- JSON dependencies: require and attributed static imports/reexports below deliver the original JSON
  text as an explicit native JSON module, without a generated JavaScript adapter.

Preparation runs after independent pin and closed-graph checks, once per
physical source. A changed source is rescanned by the production dependency
scanner without filesystem or network authority. Its runtime importer-local
specifier/style/purpose/attribute routes must exactly equal the captured routes; adding a load or
removing a side-effect dependency is an admission error. Type-only edges remain
non-authorizing. Original source pins and URL identities are not rewritten;
engine canonical hashes cover the actual delivered prepared source.

`preparation_reports()` exposes source-free ingestion hashes, normalization
witnesses and source maps. Ordinary explicitly typed JavaScript without a
hashbang stays on its existing unchanged path and has no preparation report.
Prepared source storage is shared between URL instances and bounded to 32 MiB.
Parser resource failures stop admission; they do not trigger a second parse
goal that could misclassify a CommonJS source as ESM just because the unwrapped
source fits a smaller budget. The temporary CommonJS wrapper is moved into the
engine's owned-input API without another source-buffer copy.

Executing JSX, native addons, Wasm and other builtins needs separate contracts/providers. Typed
capability-intent annotations are rejected rather than erased without their
engine obligation metadata. Implicit reclassification of JavaScript as
TypeScript is likewise rejected. These are admission errors, not empty module
shims. The broader inspection/capsule functionality remains available unchanged.

## Native JSON imports and CommonJS dependencies

A captured `.json` dependency can be delivered when every executable incoming
edge is either `require` with no attributes or a static import/reexport with the
exact map `{ type: 'json' }`, and it has no outgoing runtime routes. Filename-only
and URL-only lookup edges do not change this loading contract. This covers
explicit JSON files, CommonJS extension/index search and JSON-valued package
entrypoints, including bare requests whose conditional exports select `.json`.
For example:

```js
import settings from 'settings-package' with { type: 'json' };
export { default as defaults } from './defaults.json' with { type: 'json' };
```

The captured target's format is authoritative. Attribute spelling cannot turn
an actual extensionless or JavaScript file into JSON. A bare JSON graph entrypoint,
untyped or differently attributed JSON import, and dynamic JSON import remain
outside admission. Dynamic options are explicitly unsupported by capture;
they cannot inherit attributes from another static request. Adding an admitted
typed or require route does not approve an unsupported incoming route.

The sealed registry indexes the complete cooked map alongside importer,
specifier and request style. Dependency records, normalized-source checks and
engine requests retain that map. Every load validates attributes and format
before cached source or an initialized value can be returned. Unsupported
attributes on JavaScript, require and metadata-only requests are refused too.
The source graph and registry schemas are v3 so old attribute-free evidence
cannot approve these routes. Capsules retain raw source observations and rescan
them; changing an attribute changes the graph pin.

The registry classifies admitted JSON as `ModuleKind::Json`; the engine receives
`ModuleSyntax::Json` and the exact original text. The engine's intrinsic JSON
parser creates the value without consulting the guest's mutable `JSON.parse`.
A leading BOM is handled inside that parser. Original text preserves duplicate
members, numeric spelling, `__proto__` data keys and code-looking strings until
the engine parses them. The canonical engine record hash covers these original
bytes and the explicit JSON format.

JSON bypasses JavaScript source generation, string escaping, JavaScript parsing,
normalization and transformed-source storage. It has no preparation report,
TypeScript witness or source map. The graph's original `content_sha256` remains
the source pin; JSON does not masquerade as a JavaScript ingestion witness.
Normal source-delivery and per-chain limits count the actual original bytes,
including a BOM. Runtime parsing remains subject to engine cancellation,
memory and work limits.

The graph's existing JSON validator remains authoritative for captured
executable dependencies. Invalid or unsupported capture inputs still prevent
registry admission; this change does not expand that syntax or resource envelope.
The resolver does not evaluate JSON during construction. At execution, the
engine retains one value per canonical module identity, returns it to repeated
`require` calls and attributed static imports, and exposes only `default` through
a JSON namespace. Require and ESM access to the same canonical module share
object identity and mutations in either initialization order. ESM URL suffixes
continue to select distinct module identities. Module
authorization still runs for each request, including cache hits.

Incoming-mode validation is indexed once alongside graph routes. Repeated
physical targets share the original registered text without allocating an
escaped wrapper. These are removed allocation and parsing steps, not measured
throughput or RSS results.

## Filename resolution without executable source

Direct require.resolve requests, including recognized createRequire aliases,
have their own captured purpose. Successful file targets appear in
resolution_targets with physical identity, original byte length and SHA-256.
They are not scanned, prepared, or traversed for dependencies unless a separate
executable route reaches the same file. This supports native-addon and binary
assets, invalid JSON, invalid JavaScript and other filename-only targets.
Both purposes retain their own exact importer and request spelling even when
they select the same graph-scoped identity.

Capture still seals the original filesystem observations and target bytes under
the existing per-file, total-payload and union-of-targets limits. Capsule replay
repeats the real resolution from those sealed inputs, including negative probes;
it never reopens a live target. The separate metadata inventory prevents lookup
authority from becoming source-delivery or execution authority.

PinnedModuleRegistry::lookup_resolution returns a RegisteredResolution with no
source, syntax or dependencies. CapturedEngineResolver implements the sibling
engine's resolve_metadata API and returns ModuleMetadata. Each successful
request calls ModulePolicyHook::authorize_metadata with current context; the
default policy method refuses until an implementation explicitly supports it.
The stock capability policy requires ModuleLoad and honors request/identity
denials. No executable ModuleRecord, canonical source hash, preparation work or
evaluation-cache entry is constructed by this runtime lookup.

The engine's exact Node builtin-name inventory is independent of its executable
provider inventory. Lookup of a recognized name returns the Node spelling,
including the distinction between fs and node:fs, without requiring Builtin
execution authority or constructing a provider. Unknown reserved node: names
produce a catchable MODULE_NOT_FOUND. A successful builtin filename lookup
cannot authorize require or import of that name.

Registry summaries count executable routes and resolution routes separately,
including their respective missing outcomes. Eager resolve_chain visits only
executable routes. Source transformation must preserve the purpose of every
captured request; changing require.resolve into require, or the reverse, fails
the dependency-conservation check. Captured lookup options, indirect loaders,
and unknown computed names retain their existing explicit refusals.

## ESM URL resolution without loading assets

Direct `import.meta.resolve()` calls have a separate captured URL-lookup purpose.
The engine returns a synchronous absolute URL using the defining module's
origin and ESM import conditions. The graph records project-relative file URL
descriptors or normalized absolute non-file URLs. Relative missing paths,
directories, query strings, fragments and repeated path separators retain their
URL meaning. Existing regular files use the captured realpath; URL lookup does
not parse, prepare, evaluate or cache their contents.

File observations made only for URL lookup are stat-only capsule inputs.
A large binary asset therefore does not consume the executable-source byte
budget. Package manifests, symlink targets and negative probes remain sealed
resolution evidence. If a later executable route needs a stat-only target,
live capture verifies that the file is unchanged before reading its bytes;
replay refuses a source request when the capsule contains only metadata.
The combined target limit counts URL, filename and executable identities, and
package lookup caches distinguish these purposes.

`PinnedModuleRegistry::lookup_url_resolution` admits only the exact captured
importer and request spelling. A URL result grants neither filename-lookup nor
source-delivery authority. The adapter uses `ModuleMetadataTarget::SourceUrl`
for trusted installed file locations and `AbsoluteUrl` for captured non-file
URL strings; `Filename` remains exclusive to `require.resolve`. The engine
checks the target purpose and normalized URL before exposing the result.
Every successful lookup invokes the current `authorize_metadata` policy;
a previous successful result cannot bypass revocation.

Bare core names resolve to their `node:` URLs. Explicit `node:` URLs need
no installed executable provider and are not checked against its inventory.
Other absolute non-file schemes are normalized without fetching them.
Missing packages and blocked package exports retain their captured errors.
These outcomes remain unchanged after the live project is replaced.

The native engine retains one `import.meta` object per module. Its resolver
function keeps that module's base when extracted or called from another module,
uses ordinary string coercion, and respects replacements, accessors and deletion
of the `resolve` property. Captured graphs currently admit direct, statically
bounded requests and literal `['resolve']` access; escaping, computed or mutable
resolver origins are refused with an explicit diagnostic. Absolute file URLs
and absolute filesystem paths need an additional captured-root mapping and
remain outside this capture contract. This bounded capture support does not
claim arbitrary computed-loader completeness or full Node URL conformance.

## Authorization is per load, not per cached byte

Every returned candidate declares `RuntimeCapability::ModuleLoad`. The adapter
calls the supplied engine `ModulePolicyHook` on every request. The stock engine
`CapabilityPolicyHook` therefore refuses a request without that capability and
honors its specifier deny list. A previously allowed load is checked again after
policy changes. Returned record mutations do not modify the sealed registry.
The callback is trusted host code and receives the full candidate record,
including source, before deciding; private source is returned only on success.

`resolve_chain` streams every distinct incoming importer/style/specifier route,
including diamond edges and cycle back-edges, before deduplicating its returned
modules. A denial stops the walk and discards the prepared output vector; no
partial success is returned. It does not roll back effects a custom policy
callback performs. Traversal is deterministic breadth-first order, not ESM
evaluation order. The queue retains each module once instead of allocating a
complete vector of owned route requests. Returned source copies are bounded to
32 MiB per chain using the delivered, normalized byte lengths, including separate
URL instances; records are reused within the chain for repeated policy checks.

Engine hashes use `ModuleRecord::canonical_hash`, not the source-only SHA-256.
A per-module `OnceLock` caches only that immutable hash after authorization;
concurrent cold loads share its initialization. It retains neither a policy
result nor another copy of source. Success and failure carry current trace,
decision and policy IDs. Failure output includes the request and, when known,
target identity but no source contents. The provenance tag denotes captured
project material, not authenticated npm registry origin. `ModuleLoad` says
nothing about filesystem, network, process or other effects in the module body;
their engine checks remain necessary.

## Integration boundary and verification

This is a real engine **resolution/source-delivery** adapter, not an evaluator.
The source scanner still does not prove arbitrary runtime dependency completeness.
Unknown computed loads fail at this adapter instead of gaining ambient fallback.
Import/export binding validation, CommonJS cache initialization, execution cells,
effect authority and cyclic evaluation are not implemented by this adapter.
The product's `franken-node run --frozen-modules` path captures and prepares the
graph, then passes this resolver to the sibling engine's
`execute_resolved_entry_with_resolver`. The engine performs linking, evaluation,
native-provider delivery and per-load checks. Embedding consumers can use the
same public contract directly.

The engine-independent registry unit tests run in the regular native module-graph
suite. This separate focused host compiles the same production modules against
the real sibling engine, with no duplicated contract structs or mock resolver.
Tests cover format preparation, dependency-route conservation, replay, concurrent
hash reuse, per-edge authorization and normalized-source budgets. Native readline
and diagnostics tests execute captured CommonJS and ESM packages in both engine
lanes after live sources change, verify shared identities and subscriptions, and
exercise missing capabilities, subscriber filesystem-write denial and refused
getter mutations. JSON tests cover package/extension/index routes, cycles,
contained aliases, capsule replay after source mutation, TypeScript consumers,
independent source pins, raw-byte budgets, static attributes and reexports, and
refusal of missing/mismatched attributes even after a valid request was cached.
Native JSON fixtures poison the guest's `JSON.parse`, load one payload through
package, relative, require and typed ESM routes, and check both cache orders,
shared mutation visibility, a default-only namespace, BOM handling, duplicate
keys and `__proto__` data against Node. Replay runs after live project sources
and manifests are replaced. These tests use Node 24 as the reference runtime.
With sibling checkouts adjacent:

```sh
cargo test --manifest-path tools/module-graph/engine-bridge/Cargo.toml \
  --lib source_graph::
```

The CI job pins the engine revision used for contract verification and reports
both source revisions. Disabling optional engine sibling-service/persistence
features avoids unrelated integrations; it does not replace the module resolver,
policy hook, capabilities, normalization or canonical hashing implementations.
A listed test or configured job is not execution evidence. Inspect native build
and test results separately from Node reference checks before claiming success.
