# bd-2fqyv.2.1 Contract: Authoritative Trust-Card Registry Persistence

## Scope

This contract replaces the current live CLI shortcut that hydrated the
fixture-only `fixture_registry()` helper for trust-card and trust-control
operations. It defines the
authoritative persisted state shape, bootstrap behavior, and durability rules
for the storage-backed trust-card registry used by:

- `franken-node trust card`
- `franken-node trust list`
- `franken-node trust revoke`
- `franken-node trust quarantine`
- `franken-node trust sync`
- `franken-node trust-card show|export|list|compare|diff`

This document is the storage/bootstrap companion to
`docs/specs/section_10_4/bd-2yh_contract.md`.

## Storage Location

Default authoritative registry path:

`<project-root>/.franken-node/state/trust-card-registry.v1.json`

Resolution rules:

1. `<project-root>` is the directory containing a project-local
   `franken_node.toml`.
2. A user-global config under `~/.config/franken-node/config.toml` is not a
   valid anchor for project-scoped trust state by itself.
3. If a future explicit registry-path override is provided, that override wins.
4. If no project-local config exists and no explicit override is provided,
   operator-facing trust commands MUST fail closed instead of inventing a
   synthetic location or silently loading demo data.

The persisted registry is project-scoped state, not a global user cache.

## Snapshot Schema

The canonical serialized payload is the `TrustCardRegistrySnapshot` structure in
`crates/franken-node/src/supply_chain/trust_card.rs`.

Required fields:

- `schema_version`: must equal `franken-node/trust-card-registry-state/v1`
- `cache_ttl_secs`: persisted TTL configuration for cache rebuilds
- `cards_by_extension`: deterministic `BTreeMap<String, Vec<TrustCard>>`

Explicit non-goals:

- In-memory cache entries are not persisted.
- Telemetry buffers are not persisted.
- Demo/test fixture constructors are not part of the production snapshot schema.

## Load Validation Rules

Loading a persisted snapshot MUST reject the snapshot if any of the following
hold:

- `schema_version` is unknown
- an extension bucket is empty
- an extension bucket contains a card whose `extension.extension_id` does not
  match the bucket key
- any card signature or `card_hash` verification fails
- retained history is not strictly monotonic by `trust_card_version`
- adjacent retained versions break the `previous_version_hash` chain

On successful load, cache state is rebuilt from the latest card in each
extension history using the loader timestamp. Cache rebuild is derived state,
not authoritative state.

## Bootstrap Semantics

Normal operator-facing commands MUST NOT auto-seed from `fixture_registry()`.

Missing-state behavior:

- Read-only trust queries fail with a clear "registry not initialized" error.
- Mutating trust commands fail with the same error until an explicit bootstrap or
  import step creates the registry file.
- The initial authoritative bootstrap state is an empty snapshot with zero trust
  cards, not demo/sample cards.

The only acceptable ways to materialize non-empty initial state are:

- importing from authoritative upstream registry/trust sources
- loading a previously persisted snapshot
- explicit test-only fixture injection that is unreachable from normal operator
  command paths

## Durability Rules

Every successful mutation that changes authoritative trust state MUST persist the
full snapshot atomically:

1. serialize the full snapshot deterministically
2. write to a temp file in the destination directory
3. fsync the temp file
4. rename into place
5. fsync the parent directory where supported

If persistence fails, the mutating CLI path MUST report failure and MUST NOT
pretend the mutation became authoritative.

## Migration From Current Demo Wiring

The current `fixture_registry()` path is non-conformant for live CLI usage and must
be removed by follow-on implementation bead `bd-2fqyv.2.2`.

Migration requirements:

- existing test/demo constructors remain available only in unit/integration test
  code
- the first production loader uses empty-or-imported authoritative state
- no implicit migration from demo memory state to disk is allowed
- any future developer/demo seeding flow must be explicit, loudly labeled, and
  unreachable from normal trust operations

## Required Verification

Minimum coverage for the implementation bead:

- snapshot round-trip preserves latest-card reads
- load rejects tampered historical cards
- load rejects mismatched extension buckets
- operator-facing CLI rejects missing registry state instead of showing demo data
- mutation paths persist state and subsequent CLI invocations observe it
