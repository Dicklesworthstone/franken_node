# bd-2bj4 — Deterministic graph ingestion pipeline

## Verdict: PASS

## Implementation
- Primary ingestion module: `crates/franken-node/src/dgis/graph_ingestion.rs`
- Seed fixture and builder: `crates/franken-node/src/dgis/graph_seeds.rs`
- Integration test: `tests/security/dgis_graph_ingestion.rs`
- Realistic npm topology fixture: `tests/security/graph_seeds/realistic_npm_topology.json`
- Verification gate: `scripts/check_dgis_graph_ingestion.py`

## Verification
- `python3 scripts/check_dgis_graph_ingestion.py --json --skip-cargo` — static contract PASS, 6/6 checks.
- `python3 -m pytest tests/test_check_dgis_graph_ingestion.py -q` — 7/7 tests passed.
- `python3 -m py_compile scripts/check_dgis_graph_ingestion.py tests/test_check_dgis_graph_ingestion.py` — passed.
- `env UBS_SKIP_RUST_BUILD=1 ubs scripts/check_dgis_graph_ingestion.py tests/test_check_dgis_graph_ingestion.py artifacts/section_10_20/bd-2bj4/verification_evidence.json artifacts/section_10_20/bd-2bj4/verification_summary.md` — exit 0; 0 critical issues. The remaining warnings are Bandit subprocess warnings for the pytest helper that executes the repo-local checker with `sys.executable`.
- `git diff --check -- scripts/check_dgis_graph_ingestion.py tests/test_check_dgis_graph_ingestion.py artifacts/section_10_20/bd-2bj4/verification_evidence.json artifacts/section_10_20/bd-2bj4/verification_summary.md .beads/issues.jsonl` — passed.
- `rch status --jobs --json` — RCH job `29840908367167878` completed `cargo test -p frankenengine-node --test dgis_graph_ingestion` on `vmi1152480` with exit code 0 at `2026-05-14T07:32:39.760871653+00:00`.

## WindowedGraph Invariants
- total observations: 51
- unique observations: 51
- unique package versions: 20
- unique maintainers: 6
- unique dependency targets: 8
- minimum total nodes: 34
- minimum total edges: 56
