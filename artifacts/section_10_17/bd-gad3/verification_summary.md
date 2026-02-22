# bd-gad3 Verification Summary

- Status: **PASS**
- Checker: `scripts/check_isolation_mesh.py --json` (54/54 checks pass)
- Checker self-test: PASS (6/6)
- Python unit tests: `tests/test_check_isolation_mesh.py` (14 tests pass)

## Delivered Surface

- `docs/specs/section_10_17/bd-gad3_contract.md`
- `crates/franken-node/src/runtime/isolation_mesh.rs`
- `scripts/check_isolation_mesh.py`
- `tests/test_check_isolation_mesh.py`
- `artifacts/section_10_17/bd-gad3/verification_evidence.json`
- `artifacts/section_10_17/bd-gad3/verification_summary.md`

## Acceptance Coverage

- Workloads can be promoted to stricter rails at runtime without losing policy continuity.
- Latency-sensitive trusted workloads remain on high-performance rails within budget.
- Hot-elevation transitions are atomic: workload placement updated in single step.
- Demotion from a stricter rail to a less strict rail is explicitly forbidden (fail-closed, MESH_007).
- Mesh topology is deterministic and auditable via BTreeMap ordering and structured events.
- Latency budget enforcement rejects elevation requests that would violate budget (MESH_004).

## Key Design Decisions

- Four isolation levels ordered by strictness: Shared < ProcessIsolated < SandboxIsolated < HardwareIsolated.
- ElevationPolicy per workload controls elevation permissions, max target level, and latency budget.
- 7 event codes (MESH_001..MESH_007) for full auditability.
- 8 error codes (ERR_MESH_*) for deterministic failure classification.
- 6 invariants (INV-MESH-*) documented in both spec contract and implementation.
- 24 inline Rust unit tests covering all invariants, error paths, and happy paths.
