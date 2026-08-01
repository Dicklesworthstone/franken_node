# Engine Split Contract: franken_node depends on franken_engine

## Purpose

`franken_node` is the compatibility/product surface.
`franken_engine` is the canonical runtime core.

This repo MUST consume engine crates from `/dp/franken_engine` and MUST NOT maintain forked duplicates of those crates.

## Dependency Mapping

`crates/franken-node/Cargo.toml` uses path dependencies to:
- `../../../franken_engine/crates/franken-engine`
- `../../../franken_engine/crates/franken-extension-host`

## Rules

- Product behavior changes that require engine internals must land in `franken_engine` first.
- `franken_node` may ship on a different cadence but must pin and validate an explicit engine revision.
- No local reintroduction of `crates/franken-engine` or `crates/franken-extension-host` in this repo.

## Runtime-Evidence Authority Handoff (`bd-fzpkz`)

Runtime evidence crosses the repository boundary through the typed
`franken_engine::RuntimeEvidenceAuthority` API. The product does not call an
engine constructor that invents a signing seed, and the execution child does
not receive a long-lived product key.

The ownership and lifecycle are:

| Surface | Owner | Contract |
|---|---|---|
| Product evidence root | `franken_node` parent | Generate from OS entropy on first use and persist at `<user-state>/franken-node/runtime-evidence/keys/product-root.key` as an owner-only file outside the guest project root. Never serialize its private seed into the execution child. |
| Session evidence authority | `franken_node` parent, consumed by `franken_engine` | Generate a fresh nonzero seed for each native session, derive the public `EvidenceVerificationIdentity`, and pass the resulting typed authority through `ExecutionOrchestrator::try_new_with_runtime_config_and_authority`. |
| Public identity capture | `franken_node` parent | Sign the session nonce and complete engine verification identity with the persistent product root, then persist the capture under `<user-state>/franken-node/runtime-evidence/identity-captures/<verification-key>.json`, also outside the guest project root. |
| Child admission | supervised native-session worker | Verify the signed capture, reconstruct the authority from the short-lived seed, and reject any seed/public-identity mismatch before engine construction. When process spawning activates Bubblewrap's read-only host-root bind, mask the complete parent-owned runtime-evidence state directory with an empty `tmpfs` before launching the worker. |
| Completion reconciliation | `franken_node` parent | Reject a worker response whose evidence identity differs from the product-signed capture and surface the capture plus its durable path in `RunDispatchReport`. |
| Independent verification | operator/verifier | Pin the product root through a channel independent of the capture. The public key embedded in a capture is useful for integrity checks but is not, by itself, a trust anchor. |

The session seed may exist only for the bounded native-session handoff and
engine authority lifetime. Request buffers and the handoff grant zeroize their
seed storage when consumed or dropped. Production code must not substitute a
hard-coded seed, a process-global seed, a producer-known deterministic seed,
or a child-generated self-asserted identity. Fixed seeds are permitted only in
`cfg(test)` fixtures.

This handoff preserves the execution-cell rule below: the persistent product
root and durable captures stay outside the guest filesystem root, while each
child receives only one short-lived session authority. The user-state root is
`XDG_STATE_HOME`, then `LOCALAPPDATA` on Windows, then `$HOME/.local/state`;
startup fails closed if that location resolves inside the guest project. The
capture is independently durable even if the child crashes, and it binds the
exact engine key provenance needed to verify the session's signed evidence.
The Bubblewrap mask prevents an otherwise allowed child utility from receiving
the absolute product-root path as an argument and returning its bytes through
captured output.

## Native-Code Capsule Handoff (`NCC-NODE-SPLIT-0010-V1`)

The engine ADR
`/dp/franken_engine/docs/adr/ADR-0010-native-code-capsule-trust-boundary.md`
defines a third, lower-level sibling at `/dp/franken_native_capsule`. The ADR
is not implementation authority while its machine-readable state is
`proposed` and `implementation_authorized=false`.

If approved, the only production dependency chain is:

```text
franken_node -> franken_engine -> franken_native_capsule
```

Ownership is strict:

| Surface | Owner |
|---|---|
| JavaScript semantics, lowering to backend-neutral `NativeRegionPlan`, tier eligibility, compile/activation authorization policy, execution-cell and broker policy, deopt/replay semantics | `franken_engine` |
| NRP-to-RCO compilation/sealing, backend adapters, raw invocation, executable mappings, native relocation, W^X, platform CFI/entitlements, quiescent retirement | `/dp/franken_native_capsule` |
| Product profile UX, packaging, worker supervision, platform deployment inputs, out-of-cell broker and native-authorization service operation, key custody, commit reconciliation and operator recovery | `franken_node` |

The native-authorization service executes engine-owned policy logic outside
the execution cell. A cell may submit an unsigned, untrusted compile or
activation proposal, but it cannot mint the signed authorization, assert its
own epochs as authoritative, or fall back to an in-cell key when the signer is
unavailable, rotated, or revoked.

The capsule’s unsafe grant is package/module-scoped, not repository-wide. Its
API and worker packages remain unsafe-forbidden; only the runtime package’s
exact ADR-allowlisted raw-invocation and platform
executable-memory, unwind-registration, process-sandbox, and
process-supervisor mechanism modules may contain first-party unsafe
with invariant IDs, proof/test linkage, cfg/feature coverage, and
producer-distinct review. Build scripts, proc macros, examples, tests, benches,
generated source, and unallowlisted modules remain forbidden, while transitive
unsafe is inventoried separately.

FrankenNode owns supervisor policy and operations. If PID/handle lifecycle,
namespace/seccomp, XPC/sandbox, restricted-token/AppContainer, Job Object, or
process-mitigation setup cannot use an already-audited safe crate, the
capsule’s allowlisted platform mechanism implements it behind a narrow safe
engine API. The product still never imports or calls the capsule directly.

`franken_node` must not:

- depend on or call the capsule directly in production;
- implement a second native loader, compiler, relocation path, or
  executable-memory manager;
- add `unsafe` to invoke or recover native code;
- catch a native fault and claim same-process Tier-I fallback;
- describe compilation-worker isolation, W^X, CFI/PAC/BTI, or a compiler
  signature as arbitrary-code containment.

The untrusted-production native profile runs the complete engine execution
cell, heap, native stack, and code mappings in a long-lived child process.
`franken_node` may supervise that engine-owned process boundary and reconcile
its durable host-effect/evidence prefix, but it does not acquire engine or
capsule semantics. The high-throughput in-process profile has a larger
process-fatal failure domain and must be exposed and measured separately.
Parent address-space survival is not authority confinement. Untrusted
production additionally requires the platform least-authority sandbox and an
out-of-cell policy-enforcing broker. The child receives no ambient host
authority or long-lived signing/declassification keys. An external effect
whose commit state cannot be proven becomes a typed indeterminate terminal
outcome; it is never blindly replayed. A post-native checkpoint supplied by
the child is not trusted recovery state. Recovery begins at the last
pre-native checkpoint bound to the broker/evidence prefix, or at state
independently reconstructed and verified outside the child, and replays
broker-held nondeterminism and effect receipts. Child-supplied IFC labels,
capability/provenance assertions, evidence, and commit claims are untrusted.
The broker ignores child-supplied public labels and enforces a conservative
output label derived from all labels admitted to the cell plus broker-held
input lineage. Fine-grained language-level IFC still trusts the
engine/compiler/backend/capsule/generated-code semantic path; this contract
does not claim that the product broker can reconstruct arbitrary value-level
dataflow from a corrupted child.
Before native entry, eligibility proves prospective effects accept the
cell-high-water label; otherwise preferred mode routes the transaction to an
independently eligible Tier-I path and required mode returns a typed
doctor/explain denial. Post-entry escalation can restart in Tier I only from a
trusted pre-native boundary with broker-proved replay safety; signed
declassification remains out of cell.
The capsule repository's `franken-native-capsule-worker` is a distinct
compile-isolation process: it owns no JavaScript heap and never executes
untrusted guest code. It cannot be cited as the crash-contained execution
boundary.

Ordinary native profiles make no cache/branch-predictor/SMT/co-residency
confidentiality claim. A separately evidenced high-assurance deployment must
own core isolation/scheduling, SMT and cache/NUMA policy, predictor
mitigations, a constant-time out-of-cell key service, cross-tenant red probes,
and its measured cost. Ambient OS core dumps are disabled; any explicitly
enabled diagnostic dump is broker-written to an encrypted,
quota/retention-bounded store with no guest-chosen filename and only a
redacted operator reference.

Packaging may transitively include a pinned capsule binary or library only
through the pinned engine release. Entitlement, code-signing, notarization,
Windows-signing, Linux-package, backend, capsule-ABI, and rollback identities
must stay distinct in the platform-signing envelope.

## Proof-Carrying Host-Effect Producer Handoff (bd-f5b04.2.6)

`franken_node` owns the proof-carrying host-effect contract, not the native host
execution implementation. The first-tranche boundary is:

| Surface | Owner | Close condition |
|---|---|---|
| `fs.read`, `fs.write`, `http.request` execution | `franken_engine` via `crates/franken-engine/src/hostcall_effects_migration.rs` and its public producer boundary | A pinned engine revision flips `FullCapsHandler::dispatches_real_hostcalls() == true` because real effect execution exists. |
| Receipt contract | `franken_node` via `crates/franken-node/src/runtime/effect_receipt.rs` | Every allowed effect carries an `EffectReceipt` with result/post-state hashes; denied effects carry no result/post-state. |
| Byte backing store | `franken_node` via `crates/franken-node/src/storage/cas.rs` | Real producer bytes are stored by `ContentAddressedStore`, and receipts carry only CAS hashes. |
| Replay and verification | `franken_node` replay/verifier surfaces | `verify-replay` re-derives hashes from CAS bytes and fails closed on missing or tampered content. |
| Compatibility oracle | `franken_node` compat surfaces | First-tranche operations `compat:fs:readFile`, `compat:fs:writeFile`, and `compat:http:request` are green against the engine-produced bytes and metadata. |

Until that engine revision exists, `franken_node` must remain a fail-closed
consumer: it may define `EffectReceipt`, CAS, replay, compat-oracle, and release
gates, but it must not add a local `FsHostcallEffect`, `NetworkHostcallEffect`,
`FullCapsHandler`, `dispatches_real_hostcalls`, or `hostcall:fs:*` /
`hostcall:network` producer implementation to paper over the missing engine
boundary.

## CI Expectations

- Pinned engine matrix: pass required for product release.
- Latest engine main matrix: pass required before merge of compatibility-critical changes.
- Execution-normalization gate: `scripts/check_ownership_violations.py` enforces
  the `bd-f5b04.2.6` no-local-producer rule so the duplicate-implementation gate
  stays green only while the product layer remains a consumer of the engine
  effect producer.
