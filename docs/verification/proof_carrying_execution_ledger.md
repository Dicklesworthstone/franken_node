# Proof-Carrying Execution Ledger (PCEL) v1

`bd-2hqd.4` introduces a deterministic assurance ledger for closed-bead verification artifacts.

## Purpose

PCEL turns per-bead evidence into a reproducible proof chain:

- canonicalize each `verification_evidence.json`
- hash each canonical evidence payload and paired `verification_summary.md`
- bind dependency structure into each bead leaf
- compute a deterministic Merkle root over the selected closed-bead scope
- fail closed when required proof artifacts are missing

## Script

- Checker: `scripts/check_proof_carrying_execution_ledger.py`
- Unit tests: `tests/test_check_proof_carrying_execution_ledger.py`
- CI gate: `.github/workflows/proof-carrying-execution-ledger-gate.yml`

## Scope Selection

Default scope is closed beads with prefix `bd-2hqd`.

- Default: `--bead-prefix bd-2hqd`
- Full closed-bead sweep: `--include-all-closed`

Inputs:

- `.beads/issues.jsonl` (closed/open status + dependency edges)
- `artifacts/**/bd-*/verification_evidence.json`
- `artifacts/**/bd-*/verification_summary.md`

## Deterministic Hashing Rules

- Canonical JSON: `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
- Evidence digest: `sha256(canonical_evidence_json)`
- Summary digest: `sha256(normalized_summary_markdown)` where line endings are normalized to `\n`
- Leaf digest domain: `sha256("pcel:v1:leaf:" || canonical_leaf_payload)`
- Merkle node domain: `sha256("pcel:v1:node:" || left || right)`

## Closed-Bead Proof-Chain Gate

For each selected closed bead, PCEL verifies:

1. evidence file exists
2. summary file exists
3. evidence JSON parses and canonicalizes
4. dependency closure holds for closed dependencies within selected scope
5. Merkle root is computable

Gate verdict is `PASS` only when every check passes.

## Outputs

When run with `--build-report`, PCEL writes:

- `artifacts/assurance/proof_carrying_execution_ledger_v1.json`
- `artifacts/assurance/proof_carrying_execution_ledger_v1.md`

Key JSON fields:

- `schema_version`
- `scope`
- `summary`
- `checks`
- `dependency_map`
- `dependency_closure`
- `merkle.root_sha256`
- `content_hash`

## Commands

```bash
# Human-readable gate
python3 scripts/check_proof_carrying_execution_ledger.py

# Machine-readable gate
python3 scripts/check_proof_carrying_execution_ledger.py --json

# Emit assurance artifacts
python3 scripts/check_proof_carrying_execution_ledger.py --build-report --json

# Internal determinism/self-consistency checks
python3 scripts/check_proof_carrying_execution_ledger.py --self-test --json
```

## CI Behavior

`proof-carrying-execution-ledger-gate.yml` runs:

1. PCEL self-test
2. PCEL gate with report emission
3. Unit tests for the PCEL checker
4. Artifact upload for traceability

This provides a reproducible, machine-verifiable closed-bead evidence chain for the targeted assurance scope.
