# bd-ac83 — Remote Computation Registry

## Scope
Versioned named remote computation registry with canonical name enforcement (`domain.action.vN`) and dispatch gating via `RemoteCap`.

## Module
`crates/franken-node/src/remote/computation_registry.rs`

## Acceptance Criteria
1. Registry enforces canonical computation naming: `domain.action.vN`
2. Malformed names rejected with `ERR_MALFORMED_COMPUTATION_NAME`
3. Unknown lookups produce `ERR_UNKNOWN_COMPUTATION`
4. Duplicate registrations produce `ERR_DUPLICATE_COMPUTATION`
5. Version bumps are strictly monotonic (`ERR_REGISTRY_VERSION_REGRESSION`)
6. Dispatch requires valid `RemoteCap` with `RemoteComputation` operation
7. Catalog round-trip serialization preserves registry contents
8. All operations emit audit events with trace IDs

## Event Codes
| Code | Trigger |
|------|---------|
| CR_REGISTRY_LOADED | Registry initialized |
| CR_LOOKUP_SUCCESS | Computation found or registered |
| CR_LOOKUP_UNKNOWN | Computation not found |
| CR_LOOKUP_MALFORMED | Name fails canonical check |
| CR_VERSION_UPGRADED | Registry version bumped |
| CR_DISPATCH_GATED | Dispatch authorized or denied |
| CR_REGISTRY_REJECTED | Registry mutation rejected before state change |

## Error Codes
| Code | Trigger |
|------|---------|
| ERR_UNKNOWN_COMPUTATION | Lookup for unregistered name |
| ERR_MALFORMED_COMPUTATION_NAME | Name violates `domain.action.vN` |
| ERR_DUPLICATE_COMPUTATION | Re-registration of same name |
| ERR_REGISTRY_VERSION_REGRESSION | Non-monotonic version bump |
| ERR_INVALID_COMPUTATION_ENTRY | Missing description or schema |

## Invariants
- INV-CR-CANONICAL: All registered names match `domain.action.vN`
- INV-CR-MONOTONIC: Registry version only increases
- INV-CR-GATED: Dispatch requires valid RemoteCap
- INV-CR-AUDITABLE: All operations produce audit events

## Verification
- Script: `scripts/check_computation_registry.py`
- Tests: `tests/test_check_computation_registry.py`
- Evidence: `artifacts/section_10_14/bd-ac83/`
