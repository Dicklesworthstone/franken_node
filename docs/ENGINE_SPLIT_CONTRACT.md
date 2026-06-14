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
