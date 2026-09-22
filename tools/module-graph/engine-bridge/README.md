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

Only analyzed closed graphs with explicit JavaScript ESM/CommonJS formats are
admitted. `.mjs`, `.cjs`, and `.js` with captured package `type` are supported.
Unmarked JavaScript needs engine syntax detection; TypeScript/JSX needs an
explicit normalization path; JSON, native addons, Wasm and builtins require
separate providers. These are admission errors, not empty module shims. The
existing broader inspection/capsule functionality remains available unchanged.

## Authorization is per load, not per cached byte

Every returned candidate declares `RuntimeCapability::ModuleLoad`. The adapter
calls the supplied engine `ModulePolicyHook` on every request. The stock engine
`CapabilityPolicyHook` therefore refuses a request without that capability and
honors its specifier deny list. A previously allowed load is checked again after
policy changes. Returned record mutations do not modify the sealed registry.
The callback is trusted host code and receives the full candidate record,
including source, before deciding; private source is returned only on success.

`resolve_chain` checks every distinct incoming importer/style/specifier route,
including diamond edges and cycle back-edges, before deduplicating its returned
modules. A denial discards the entire prepared vector; no partial success is
returned. It does not roll back effects a custom policy callback performs.
Traversal is deterministic breadth-first order, not ESM evaluation order.
Returned source copies are bounded to 32 MiB per chain, including separate URL
instances; cached records are reused for repeated policy checks.

Engine hashes use `ModuleRecord::canonical_hash`, not the source-only SHA-256.
Success and failure carry current trace, decision and policy IDs. Failure output
includes the request and, when known, target identity but no source contents.
The provenance tag denotes captured project material, not authenticated npm
registry origin. `ModuleLoad` says nothing about filesystem, network, process or
other effects in the module body; their engine checks remain necessary.

## Integration boundary and verification

This is a real engine **resolution/source-delivery** adapter, not an evaluator.
The source scanner still does not prove arbitrary runtime dependency completeness.
Unknown computed loads fail at this adapter instead of gaining ambient fallback.
Import/export binding validation, CommonJS cache initialization, execution cells,
effect authority, cyclic evaluation and engine normalization are not implemented
by this adapter. `ExecutionOrchestrator`'s current single-package execution path
does not accept a resolver injection, so `franken-node run` is not changed here.
Embedding consumers that accept the public engine trait can use it directly.

The engine-independent registry's fifteen unit tests run in the regular native
module-graph suite. This separate focused host compiles the same production
modules against the real sibling engine, with no duplicated contract structs or
mock resolver. With sibling checkouts adjacent to one another:

```sh
cargo test --manifest-path tools/module-graph/engine-bridge/Cargo.toml \
  --lib engine_resolver::tests
```

The CI job pins the engine revision used for contract verification and reports
both source revisions. Disabling optional engine sibling-service/persistence
features avoids unrelated integrations; it does not replace the module resolver,
policy hook, capabilities or canonical hashing implementations being tested.
