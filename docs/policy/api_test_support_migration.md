# API Test-Support Feature Migration Path

**Beads:** bd-2mt88, bd-2mt88.1
**Origin commit:** f3aa5372e45353c3698689527a9f1d01d864228e
**Origin date:** 2026-04-23
**Scope:** `crates/franken-node/src/api/mod.rs`, `crates/franken-node/src/api/middleware.rs`, `crates/franken-node/src/api/fleet_quarantine.rs`

## Purpose

Commit `f3aa5372` tightened direct `test-support` feature gates around API and control-plane items. This document is the deprecation and migration path for downstream users that previously treated `test-support` as a way to compile production API surfaces.

`test-support` is a harness feature. `control-plane` is the API ownership feature. The current crate feature `test-support` still composes `control-plane` and `admin-tools` for repository test harnesses, but downstream crates should not rely on `test-support` as the API feature.

## What Changed

The public `crate::api` namespace is now owned by `control-plane` at `crates/franken-node/src/lib.rs`. Once the namespace is enabled, `crates/franken-node/src/api/mod.rs` declares `operator_routes`, `session_auth`, `middleware`, and `fleet_quarantine` as normal API modules so module wiring does not drift through per-module `cfg` toggles.

The direct item gates that previously used `test-support` were moved to `control-plane` or `#[cfg(test)]` where they belong:

| Surface | Previous downstream assumption | Migration |
| --- | --- | --- |
| `operator_routes` | Enable `test-support` to reach operator control routes. | Enable `control-plane` for API use. Use `extended-surfaces` only when intentionally enabling the legacy umbrella feature set. |
| `session_auth` | Enable `test-support` to reach session-authenticated control helpers. | Enable `control-plane`; keep harness-only helpers behind `#[cfg(test)]` or explicit test fixtures. |
| `api::middleware` | Enable `test-support` for auth, route metadata, and trace helpers. | Enable `control-plane` for middleware primitives. Unit tests use `#[cfg(test)]`; downstream integration tests should request `control-plane`. |
| `fleet_quarantine::QuarantineRequest` | Enable `test-support` to build mutating fleet quarantine requests. | Enable `control-plane`; mutating fleet request and handler surfaces are not test-support-owned. |
| `fleet_quarantine::RevokeRequest` | Enable `test-support` to build mutating fleet revocation requests. | Enable `control-plane`; revocation is a production control-plane operation. |
| `fleet_quarantine::quarantine_route_metadata` | Enable `test-support` for route metadata. | Enable `control-plane`; route metadata is part of the control-plane API contract. |

## Remaining Direct `test-support` API Reference

The only direct `feature = "test-support"` reference left under `crates/franken-node/src/api/**` is `fleet_quarantine::StatusRequest`.

`StatusRequest` is intentionally lower risk than the removed surfaces:

- It models the read-only `GET /v1/fleet/status` request payload.
- It does not grant route metadata, handler dispatch, operator startup, session authentication, quarantine, revocation, release, or reconcile authority.
- Its matching route metadata and handlers remain owned by `control-plane`.

This remaining direct gate is documented so future cleanup can decide whether to keep it as a fixture convenience or move it fully to `control-plane`. It is not a precedent for adding new direct `test-support` API gates.

## Downstream Migration Rules

1. For production or integration access to `crate::api`, depend on `frankenengine-node` with `features = ["control-plane"]`.
2. If a crate needs the old broad product surface, use `features = ["extended-surfaces"]` and understand that it enables more than API control-plane code.
3. Use `features = ["test-support"]` only for repository harness utilities. Do not rely on `test-support` as the API feature.
4. For unit tests inside this crate, prefer `#[cfg(test)]` helpers over public test-support gates.
5. For fleet quarantine integration tests, build mutating request and handler paths through `control-plane`; use `StatusRequest` only for read-only status request fixture construction.

## Verification

The executable closeout gate is:

```bash
python3 scripts/check_api_test_support_migration.py --json
```

The gate checks the current feature contract, the direct `test-support` API reference inventory, this migration path, and the `bd-2mt88.1` close reason.
