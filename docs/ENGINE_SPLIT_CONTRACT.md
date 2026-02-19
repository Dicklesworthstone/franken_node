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

## CI Expectations

- Pinned engine matrix: pass required for product release.
- Latest engine main matrix: pass required before merge of compatibility-critical changes.
