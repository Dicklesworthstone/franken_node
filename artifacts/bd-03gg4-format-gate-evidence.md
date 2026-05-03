# bd-03gg4 Format Gate Evidence

## Goal

Restore `rch exec -- cargo fmt --check` as a clean repository-wide validation
signal without broadening into unrelated compile failures.

## Before

Command:

```text
rch exec -- cargo fmt --check
```

Result: exit 1.

Primary blockers:

- `crates/franken-node/src/repair/proof_carrying_decode.rs`: rustfmt could not parse `decode` because inline negative-path regression code was embedded after the return path and the surrounding function/impl braces were malformed.
- Formatter drift was also reported across CLI, conformance, fleet, remote, replay, runtime, security, supply-chain, and test files.

After the parse repair, the same command exposed one stale module path:

```text
Error writing files: failed to resolve mod `fuzz_smoke_tests`: /data/projects/franken_node/crates/franken-node/src/supply_chain/trust_card/fuzz_smoke_tests.rs does not exist
```

The existing smoke module file was
`crates/franken-node/src/supply_chain/trust_card_fuzz_test.rs`; `trust_card.rs`
now points that test-only module declaration at the existing file.

## After

Command:

```text
rch exec -- cargo fmt --check
```

Result: exit 0.

Additional check:

```text
git diff --check
```

Result: exit 0.

## Non-Format Validation

Command:

```text
rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_node_icypine_bd03gg4 CARGO_INCREMENTAL=0 cargo check -p frankenengine-node --tests
```

Result: exit 101 after remote execution on worker `ts2`.

This is not a formatting failure. The check reaches test target
`migration_e2e_gate_artifacts` and fails in stale BPET migration-gate test code.
Representative errors:

- `RolloutHealth` has no field `stability`; available fields are `stability_score` and `risk_level`.
- `generate_fallback_plan` is not found.
- `evaluate_rollout_health` is called with `RolloutPlan`/`RolloutHealth`, but expects `StagedRolloutPlan`/`RolloutHealthSnapshot`.
- local test `RolloutPlan` lacks `Serialize` and `Deserialize`.
- `gather_evidence_requirements` is not found; rustc suggests `derive_evidence_requirements`.
- `BpetMigrationGate` is undeclared.
- `StagedRolloutPlan` has no `canary` field; available fields are `steps` and `fallback`.

Follow-up filed: `bd-yy2qb`.

`cargo clippy --all-targets -- -D warnings` was not run because the required
test compile check is blocked by `bd-yy2qb`.

## UBS

Command:

```text
ubs $(git diff --name-only --cached)
```

Result: exit 1 after scanning 33 staged Rust files in a shadow workspace.

UBS internal validation sections reported formatting, clippy, cargo check, and
test-build checks clean. The nonzero exit came from broad preexisting heuristic
inventories on files touched by the format sweep, including thousands of
unwrap/expect, panic/assert, direct-indexing, and test harness findings.

Follow-up filed: `bd-1n745`.
