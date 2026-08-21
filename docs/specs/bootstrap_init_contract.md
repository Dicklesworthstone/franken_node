# Bootstrap Init Contract (`bd-32e`)

## Goal

`franken-node init` must bootstrap deterministic project config/profile artifacts with explicit non-destructive file handling.

## Command Surface

- `franken-node init [--profile <profile>] [--config <path>] [--out-dir <dir>]`
- `--overwrite` replaces existing generated files in `--out-dir`.
- `--backup-existing` creates `*.bak.<timestamp>` backups before replacement.
- `--json` emits machine-readable init report.
- `--trace-id <id>` binds init report/diagnostics to a stable correlation ID.

## Generated Files

When `--out-dir` is provided:

- `franken_node.toml`
- `franken_node.profile_examples.toml`

When `--out-dir` is omitted:

- resolved `franken_node.toml` content is emitted to stdout
- no files are written

## Overwrite Policy (Explicit, Non-Destructive by Default)

| Condition | Behavior |
|---|---|
| target files absent | create files |
| target exists + no overwrite flags | abort with actionable error |
| `--overwrite` | replace existing files |
| `--backup-existing` | backup then replace existing files |
| `--overwrite` + `--backup-existing` | reject (mutually exclusive) |

## Determinism Contract

For equivalent inputs (resolved config and flags):

- generated config bytes are deterministic
- generated template bytes are deterministic
- report shape and field ordering are stable
- file action semantics are stable (`created`, `overwritten`, `backed_up_and_overwritten`)

`generated_at_utc` and backup filename timestamp suffixes are expected runtime metadata.

## Machine-Readable Init Report

Top-level fields:

- `schema_version` (`franken-node/init-cli/v1`)
- `command`
- `trace_id`
- `generated_at_utc`
- `selected_profile`
- `source_path`
- `wrote_to_stdout`
- `stdout_config_toml`
- `file_actions[]` with:
  - `path`
  - `action`
  - `backup_path`
- `merge_decision_count`
- `merge_decisions[]`

## CI Artifacts (`bd-32e`)

- `artifacts/section_bootstrap/bd-32e/init_contract_checks.json`
- `artifacts/section_bootstrap/bd-32e/init_snapshots.json`
- `artifacts/section_bootstrap/bd-32e/verification_evidence.json`
- `artifacts/section_bootstrap/bd-32e/verification_summary.md`
