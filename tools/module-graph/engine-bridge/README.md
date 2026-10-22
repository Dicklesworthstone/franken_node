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

## Closed-world behavior

Admission consumes the capture and builds immutable, `Send + Sync` source
storage. Sources sharing a physical path share their storage, while ESM URL
instances remain distinct identities. IDs are domain-separated, graph-scoped
opaque strings. Changing any graph input changes those IDs; a referrer from an
older capture cannot be reused with the new registry. They are not filesystem
paths or JavaScript URLs to parse or reopen.

Only the entrypoint's generated request is accepted without a referrer.
Subsequent requests must use the returned engine record ID as referrer and the
exact captured specifier and import/require style. Knowing a target's canonical
ID does not create a new edge to it. Nested package versions, condition choices,
workspace links and missing lookup decisions are never reinterpreted using the
ambient machine. Unknown requests fail rather than falling back to another
resolver. Engine requests must use `NodeCompat`; the helper entry request does
this explicitly. These captured choices cannot be relabelled Native or Bun.

Captured `require` and dynamic `import()` absences remain terminal after later
installation or capsule replay. The engine throws `MODULE_NOT_FOUND` for require
and rejects the import promise with `ERR_MODULE_NOT_FOUND`. Missing static
imports, invalid metadata, denied exports and unknown routes remain refusals.
Eager `resolve_chain` fails on any missing target.

Only analyzed closed graphs are admitted. The engine-independent
`PinnedModuleRegistry::new` remains transform-free and requires explicit
JavaScript ESM/CommonJS formats. The engine-backed constructor additionally
prepares the following captured sources using the real sibling front end:

- Unmarked `.js` and extensionless JavaScript: the engine parser tests a CommonJS
  function body first, then an ES module. This accounts for top-level return and
  lexical conflicts with CommonJS wrapper parameters without a second parser or
  a text-based import/export heuristic. The detection wrapper is never delivered.
- Explicit `.mts` and `.cts`: the engine's public source-preparation function
  normalizes supported TypeScript, with ESM/CommonJS format fixed by extension.
  Plain `.ts` uses the package scope captured by the file resolver; an explicit
  unmarked-scope observation permits engine syntax detection. No live manifest
  read or implicit `.ts` extension/index search is added during preparation.
- JavaScript hashbangs: the same engine source-preparation function handles them.
- JSON dependencies: the require-only contract below delivers a quoted
  JavaScript adapter, validated by the engine and the same dependency scanner.

Preparation runs after independent pin and closed-graph checks, once per
physical source. A changed source is rescanned by the production dependency
scanner without filesystem or network authority. Its runtime importer-local
specifier/style routes must exactly equal the captured routes; adding a load or
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

JSX, native addons, Wasm and builtins need separate contracts/providers. Typed
capability-intent annotations are rejected rather than erased without their
engine obligation metadata. Implicit reclassification of JavaScript as
TypeScript is likewise rejected. These are admission errors, not empty module
shims. The broader inspection/capsule functionality remains available unchanged.

## CommonJS JSON dependencies

A captured `.json` dependency can be delivered when every non-type-only incoming
edge is `require`, it has no outgoing runtime routes, and it has no URL-instance
suffix. This covers explicit JSON files, existing CommonJS extension/index
search and JSON-valued package entrypoints. A bare JSON graph entrypoint, static
or dynamic ESM JSON import, reexport, or mixed require/import access is refused
with `ERR_MODULE_ENGINE_JSON_IMPORT`. The graph has no import-attribute evidence
or shared ESM/CJS JSON namespace contract; knowing a target is JSON is not enough
to authorize those semantics. No optional fallback loader is added.

The original JSON text is encoded into one string literal in
`module.exports = JSON.parse(<literal>);`. It is never emitted as a JavaScript
object literal or reconstructed from a host `serde_json::Value`. Value creation
therefore belongs to the engine's `JSON.parse`, as in its native CommonJS JSON
loader: the adapter does not erase duplicate members, round numbers on the host,
turn `__proto__` into object-literal prototype syntax, or interpret code-looking
JSON strings as dependency requests. The engine frontend must preserve the
adapter exactly and accept its CommonJS parse goal. The generated JavaScript
is rescanned and must still have no dependency routes.

The existing graph JSON validator remains authoritative. This change does not
expand its accepted JSON syntax or resource envelope; invalid or unsupported
capture inputs still prevent registry admission. It does not evaluate JSON while
constructing the resolver, implement module evaluation caches, or certify an
engine's complete JSON conformance.

For these modules, `json_source_sha256` in the preparation report pins the
original captured JSON bytes. `source_ingestion` hashes describe the generated
JavaScript adapter, not an original JSON parser witness. No TypeScript witness
or source map is invented. Original graph pins and canonical identities remain
unchanged, while the engine record hash covers the delivered adapter. Source
text is absent from these summaries.

Escaping writes directly to a bounded output buffer using the remaining shared
prepared-source budget. Oversized adapters return no partial success. Repeated
physical targets share one preparation; incoming-mode validation is indexed
once alongside the graph routes rather than rescanning every edge per file.
The per-chain limit counts delivered adapter bytes, including escaping and the
wrapper, not only original JSON byte lengths. These are logical byte bounds,
not a process-RSS guarantee or a measured throughput claim.

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
`ExecutionOrchestrator`'s current single-package execution path does not accept a
resolver injection, so `franken-node run` is not changed here. Embedding consumers
that accept the public engine trait can use it directly.

The engine-independent registry unit tests run in the regular native module-graph
suite. This separate focused host compiles the same production modules against
the real sibling engine, with no duplicated contract structs or mock resolver.
Tests cover format preparation, dependency-route conservation, replay, concurrent
hash reuse, per-edge authorization and normalized-source budgets. JSON tests also
cover package/extension/index routes, cycles, contained aliases, capsule replay
after source mutation, TypeScript consumers, independent source pins, and refusal
of unsupported ESM and partial-budget cases. With sibling checkouts adjacent:

```sh
cargo test --manifest-path tools/module-graph/engine-bridge/Cargo.toml \
  --lib engine_resolver::
```

The CI job pins the engine revision used for contract verification and reports
both source revisions. Disabling optional engine sibling-service/persistence
features avoids unrelated integrations; it does not replace the module resolver,
policy hook, capabilities, normalization or canonical hashing implementations.
A listed test or configured job is not execution evidence. Inspect native build
and test results separately from Node reference checks before claiming success.
