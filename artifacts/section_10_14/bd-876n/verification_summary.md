# bd-876n: Cancellation Injection Verification Summary

**Section:** 10.14
**Bead:** bd-876n
**Refreshed:** 2026-05-13T09:20:34Z
**Verdict:** PASS

## Scope Boundary

This artifact verifies the deterministic cancellation-injection lab framework
for critical control workflows. It proves that the registered default workflow
matrix covers every declared workflow/await-point pair and that the gate/test
suite exercises leak checks, half-commit checks, invalid references, audit
export, and bounded matrix behavior.

It does not claim that production async cancellation has been injected into
every runtime await site.

## Covered Matrix

| Workflow | Await Points | Upstream Bead |
|---|---:|---|
| `epoch_transition_barrier` | 6 | `bd-2wsm` |
| `marker_stream_append` | 4 | `bd-126h` |
| `root_pointer_publication` | 4 | `bd-nwhn` |
| `evidence_commit` | 4 | n/a |
| `eviction_saga` | 6 | `bd-1ru2` |

Total default matrix cases: 24. Minimum required by the gate: 20.

## Evidence

| Artifact | Result |
|---|---|
| `crates/franken-node/src/control_plane/cancellation_injection.rs` | Framework plus 42 inline Rust tests |
| `scripts/check_cancellation_injection.py --json` | 33/33 checks passed |
| `scripts/check_cancellation_injection.py --self-test` | 33 checks OK |
| `tests/test_check_cancellation_injection.py` | 41/41 pytest tests passed |
| `docs/specs/section_10_14/bd-876n_contract.md` | Workflow matrix and invariants aligned |

## Invariants

- `INV-CANCEL-LEAK-FREE`
- `INV-CANCEL-HALFCOMMIT-FREE`
- `INV-CANCEL-MATRIX-COMPLETE`
- `INV-CANCEL-DETERMINISTIC`
- `INV-CANCEL-BARRIER-SAFE`
- `INV-CANCEL-SAGA-SAFE`

## Validation Commands

- `python3 scripts/check_cancellation_injection.py --json`: PASS, 33/33 checks
- `python3 scripts/check_cancellation_injection.py --self-test`: PASS
- `python3 -m pytest tests/test_check_cancellation_injection.py`: PASS, 41 tests
- `rg -c '#\[test\]' crates/franken-node/src/control_plane/cancellation_injection.rs`: 42 inline Rust tests
