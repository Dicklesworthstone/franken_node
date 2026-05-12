# Test Coverage Gate — FAIL

_Bead:_ `bd-17ds.6`  _Evaluated:_ `2026-05-12T19:01:26Z`

## Verdict
**FAIL** (4/5 checks pass)

## Checks

| Check | Target | Actual | Pass |
|-------|--------|--------|:---:|
| `rust_test_count` | 7060 | 23652 | ✓ |
| `e2e_scenario_count` | 6 | 44 | ✓ |
| `cross_module_integration_count` | 50 | 61 | ✓ |
| `script_logging_ratio` | >= 1.00 (445 scripts) | 396/445 = 0.890 | ✗ |
| `mock_patterns_in_prod_files` | 0 | 0 | ✓ |

## Section beads (6 total)
- closed: 0
- open: 6

## How to interpret

- This gate runs at any time and reports a snapshot. It does NOT alter the bead store.
- Targets are from the bd-17ds epic body (2026-02-24 baseline).
- Re-run after landing test work to track progress: `python scripts/check_test_coverage_gate.py`
