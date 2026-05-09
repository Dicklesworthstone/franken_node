# bd-3ex: Verifier CLI Conformance Contract Tests

**Section:** 10.7 -- Compatibility Testing Infrastructure
**Status:** Implemented
**Artifacts:** `spec/verifier_cli_contract.toml`, `tests/contract/snapshots/`

## Purpose

Establishes contract tests that pin the verifier CLI's observable behavior (`franken-node verify` subcommands), detect unintended breaking changes, and require explicit version bumps when intentional breaking changes are made. The contract covers input formats, output JSON schema, exit codes, error message format, and command-line flag inventory.

## Contract Definition

The contract is defined in `spec/verifier_cli_contract.toml` and specifies:

| Aspect | Details |
|--------|---------|
| Contract version | `3.0.0` (semver, major=3) |
| Schema version | `verifier-cli-contract-v1` |
| Subcommands | `verify module`, `verify migration`, `verify compatibility`, `verify corpus` |
| Exit codes | 0=pass, 1=fail, 2=error/invalid-input, 3=skipped/internal-error |
| Error format | Structured JSON with `error_code`, `message`, `remediation` |
| Compat policy | Supports current major (3) and one previous major (2) via `--compat-version` |

## Required JSON Output Fields

All `--json` output from verify subcommands must include:

| Field | Type | Description |
|-------|------|-------------|
| `command` | string | Subcommand invoked (e.g. `verify module`) |
| `contract_version` | string | Embedded semver contract version |
| `schema_version` | string | Schema version tag |
| `compat_version` | u16/null | Requested compat version or null |
| `verdict` | string | PASS, FAIL, SKIPPED, or ERROR |
| `status` | string | Machine-readable status |
| `exit_code` | integer | Exit code the process will use |
| `reason` | string | Human-readable explanation |

## Snapshot Policy

- Pinned expected outputs are stored in `tests/contract/snapshots/`.
- Adding new fields is non-breaking (additive-only).
- Removing or changing existing fields is breaking and requires a major version bump.
- `--update-snapshots` flag regenerates expected outputs for non-breaking changes only.
- Authoritative checks execute a real verifier runner from `--binary`, `FRANKEN_NODE_VERIFY_BIN`, or `target/debug/franken-node`; missing runners fail closed.

## Invariants

| Invariant | Description |
|-----------|-------------|
| INV-CLI-VERSION | `contract_version` in JSON output matches the contract definition |
| INV-CLI-EXIT | `exit_code` in JSON output matches the actual process exit code |
| INV-CLI-COMPAT | `--compat-version` accepts current and previous major; rejects others with exit 2 |
| INV-CLI-SUBCOMMANDS | All four verify subcommands are wired and produce structured output |
| INV-CLI-JSON-REQUIRED | All required JSON fields are present in `--json` output |
| INV-CLI-BREAKING | Removing/renaming a required field is breaking, requiring major version bump |

## Gate Behavior

The gate script `scripts/check_verifier_contract.py` validates:

1. Contract TOML loads and contains required sections
2. Exit code taxonomy matches expected 0/1/2/3 mapping
3. Error format contract specifies required fields
4. All required command IDs are defined
5. CLI source (`cli.rs`) exposes matching VerifyCommand variants
6. Main source (`main.rs`) routes all required verifier subcommands
7. At least 5 contract scenarios exist
8. Default scenario coverage for each required command
9. A configured verifier runner is executable
10. Each scenario executes as a subprocess and emits parseable JSON
11. Reported JSON `exit_code` matches the actual subprocess exit code
12. Snapshot files exist, parse as valid JSON, and compare against real subprocess output
13. Breaking change enforcement: no breaking changes without major version bump

Exit 0 on PASS, exit 1 on FAIL.

## Scenario Coverage

| Scenario ID | Command | Compat Version | Expected Outcome |
|-------------|---------|----------------|------------------|
| verify_module_default | verify-module | none | PASS (exit 0) |
| verify_migration_default | verify-migration | none | PASS (exit 0) |
| verify_compatibility_default | verify-compatibility | none | PASS (exit 0) |
| verify_corpus_default | verify-corpus | none | PASS (exit 0) |
| verify_module_invalid_compat | verify-module | 9 (invalid) | ERROR (exit 2) |

## Test Coverage

- Python gate script with `--json`, `--self-test`, and `--update-snapshots` modes
- Pytest/unittest suite covering:
  - Self-test validation
  - Full contract PASS with an explicit subprocess fixture harness
  - Snapshot comparison (exact, additive, breaking)
  - CLI subprocess JSON output
  - Missing runner fail-closed behavior
  - JSON/process exit-code mismatch rejection
  - Additive snapshot update path
  - Breaking change detection without major bump
