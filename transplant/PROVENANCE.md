# Transplant Snapshot Provenance — `pi_agent_rust`

## Source repository

- Path: `/data/projects/pi_agent_rust`
- Original snapshot date (per `TRANSPLANT_MANIFEST.md`): **2026-02-20**
- Original snapshot author: CrimsonCrane (claude-code / opus-4.6)
- Restoration date (this rehydration): **2026-05-12**
- franken_node HEAD at restoration: `d8817159651a00c2abd712429c6d51feaadfc1d8`

## Restoration method

The on-disk snapshot at `transplant/pi_agent_rust/` was previously absent from
this working tree (see bd-1qz.1 audit-debt finding) even though both
`TRANSPLANT_MANIFEST.md` and the 375-line `TRANSPLANT_LOCKFILE.sha256`
referenced 369 files.

Rehydration was driven by `transplant/restore_snapshot.sh`, which:

1. Parses `transplant/transplant_manifest.txt` (sorted, deduped, comment/blank-stripped).
2. For each relative path, copies `<source-root>/<path>` to
   `<snapshot-dir>/<path>` using `cp -p` to preserve permissions.
3. Normalizes the mtime of every copied file via `touch -d 1970-01-01T00:00:00Z`
   so subsequent hashing / diffing of the rehydrated tree is reproducible
   regardless of when the script was run.
4. Refuses to overwrite existing snapshot files unless `--force` is given.
5. Rejects any manifest entry containing `..` or a leading `/` before touching the
   filesystem (path-traversal hardening).
6. Returns exit code 0 (full success), 1 (partial — some manifest entries had no
   source file), or 2 (error). Missing-source paths are surfaced on stderr and
   reproduced below.

Lockfile contents (`TRANSPLANT_LOCKFILE.sha256`, 369 entries) were **not**
regenerated; the lockfile remains the snapshot integrity baseline against which
divergence is measured.

## Restoration results (2026-05-12)

| Metric                                          | Count |
|-------------------------------------------------|-------|
| Manifest entries                                | 369   |
| Files copied into `transplant/pi_agent_rust/`   | 367   |
| Files missing at source (could not be copied)   | 2     |

Subsequent run of `transplant/verify_lockfile.sh` reported:

| Metric                          | Count |
|---------------------------------|-------|
| `verified_ok` (hash matches)    | 259   |
| `mismatched` (source drifted)   | 108   |
| `missing` (no file in snapshot) | 2     |
| `extra` (not in lockfile)       | 0     |
| `parse_errors`                  | 0     |
| Final verdict                   | `FAIL:MISMATCH` |
| Exit status                     | 1     |

`FAIL:MISMATCH` is the **expected outcome** for this rehydration: the upstream
`pi_agent_rust` repo has continued to evolve since the snapshot was captured on
2026-02-20, so 110 of the 369 manifest paths now diverge from the lockfile
baseline. The remaining 259 paths still hash-match the original snapshot.

## Known divergences (110 of 369)

These divergences are recorded here per bd-1qz / bd-1qz.1: the snapshot has
been rehydrated from the current state of the source repo, but the lockfile
is intentionally **not** regenerated. Any consumer that needs the byte-exact
2026-02-20 snapshot must source it from history rather than the working tree.

A follow-up bead (to be filed) should decide, per category, whether to:

- accept the drift and regenerate the lockfile from the rehydrated tree, or
- pin specific files from the original snapshot via git history.

### Hash mismatches (source drifted since lockfile) (108)

**`docs/`**
- `docs/conformance-operator-playbook.md`
- `docs/extension-architecture.md`
- `docs/extension-artifact-provenance.json`
- `docs/extension-candidate-pool.json`
- `docs/extension-compatibility-matrix.md`
- `docs/extension-conformance-test-plan.json`
- `docs/extension-entry-scan.json`
- `docs/extension-inclusion-list.json`
- `docs/extension-master-catalog.json`
- `docs/extension-runtime-threat-model.md`
- `docs/extension-sample.json`
- `docs/extension-troubleshooting.md`

**`src/`**
- `src/conformance.rs`
- `src/extension_conformance_matrix.rs`
- `src/extension_dispatcher.rs`
- `src/extension_events.rs`
- `src/extension_index.rs`
- `src/extension_license.rs`
- `src/extension_popularity.rs`
- `src/extension_preflight.rs`
- `src/extension_replay.rs`
- `src/extension_scoring.rs`
- `src/extension_tools.rs`
- `src/extension_validation.rs`
- `src/extensions.rs`
- `src/extensions_js.rs`
- `src/hostcall_amac.rs`
- `src/hostcall_queue.rs`
- `src/hostcall_s3_fifo.rs`
- `src/hostcall_trace_jit.rs`

**`tests/`**
- `tests/capability_policy_scoped.rs`
- `tests/capability_prompt.rs`
- `tests/conformance/fixture_runner.rs`
- `tests/conformance/fixtures/bash_tool.json`
- `tests/conformance/fixtures/cli_flags.json`
- `tests/conformance/fixtures/edit_tool.json`
- `tests/conformance/fixtures/find_tool.json`
- `tests/conformance/fixtures/grep_tool.json`
- `tests/conformance/fixtures/ls_tool.json`
- `tests/conformance/fixtures/read_tool.json`
- `tests/conformance/fixtures/truncation.json`
- `tests/conformance/fixtures/write_tool.json`
- `tests/conformance/mod.rs`
- `tests/conformance_comparator.rs`
- `tests/conformance_fixtures.rs`
- `tests/conformance_mock.rs`
- `tests/conformance_regression_gate.rs`
- `tests/ext_conformance.rs`
- `tests/ext_conformance/API_USAGE_MATRIX.md`
- `tests/ext_conformance/VALIDATED_MANIFEST.json`
- `tests/ext_conformance/api_usage_matrix.json`
- `tests/ext_conformance/event_payloads/event_payloads.json`
- `tests/ext_conformance/fixtures/custom-provider-anthropic.json`
- `tests/ext_conformance/fixtures/custom-provider-qwen-cli.json`
- `tests/ext_conformance/fixtures/doom-overlay.json`
- `tests/ext_conformance/fixtures/dynamic-resources.json`
- `tests/ext_conformance/fixtures/git-checkpoint.json`
- `tests/ext_conformance/fixtures/hello.json`
- `tests/ext_conformance/fixtures/inline-bash.json`
- `tests/ext_conformance/fixtures/minimal_command.json`
- `tests/ext_conformance/fixtures/minimal_configuration.json`
- `tests/ext_conformance/fixtures/minimal_event.json`
- `tests/ext_conformance/fixtures/minimal_mcp.json`
- `tests/ext_conformance/fixtures/minimal_multi.json`
- `tests/ext_conformance/fixtures/minimal_provider.json`
- `tests/ext_conformance/fixtures/minimal_resources.json`
- `tests/ext_conformance/fixtures/minimal_template.json`
- `tests/ext_conformance/fixtures/minimal_tool.json`
- `tests/ext_conformance/fixtures/minimal_ui_component.json`
- `tests/ext_conformance/fixtures/npm__qualisero-pi-agent-scip.json`
- `tests/ext_conformance/fixtures/permission-gate.json`
- `tests/ext_conformance/fixtures/plan-mode.json`
- `tests/ext_conformance/fixtures/protected-paths.json`
- `tests/ext_conformance/fixtures/sandbox.json`
- `tests/ext_conformance/fixtures/status-line.json`
- `tests/ext_conformance/fixtures/subagent.json`
- `tests/ext_conformance/fixtures/todo.json`
- `tests/ext_conformance/fixtures/with-deps.json`
- `tests/ext_conformance/reports/COMPATIBILITY_SUMMARY.md`
- `tests/ext_conformance/reports/CONFORMANCE_REPORT.md`
- `tests/ext_conformance/reports/conformance_baseline.json`
- `tests/ext_conformance/reports/conformance_summary.json`
- `tests/ext_conformance/reports/gate/must_pass_events.jsonl`
- `tests/ext_conformance/reports/gate/must_pass_gate_report.md`
- `tests/ext_conformance/reports/gate/must_pass_gate_verdict.json`
- `tests/ext_conformance_artifacts.rs`
- `tests/ext_conformance_diff.rs`
- `tests/ext_conformance_fixture_schema.rs`
- `tests/ext_conformance_generated.rs`
- `tests/ext_conformance_guard.rs`
- `tests/ext_conformance_matrix.rs`
- `tests/ext_conformance_scenarios.rs`
- `tests/ext_conformance_shapes.rs`
- `tests/extension_scoring_ope.rs`
- `tests/extension_scoring_voi_meanfield.rs`
- `tests/extension_validation.rs`
- `tests/extensions_concurrent_correctness.rs`
- `tests/extensions_event_cancellation.rs`
- `tests/extensions_event_wiring.rs`
- `tests/extensions_fs_shim.rs`
- `tests/extensions_oco_heterogeneous.rs`
- `tests/extensions_process_shim.rs`
- `tests/extensions_provider_oauth.rs`
- `tests/extensions_provider_streaming.rs`
- `tests/extensions_repair_events.rs`
- `tests/extensions_stress.rs`
- `tests/hostcall_queue_ebr.rs`
- `tests/hostcall_queue_loom.rs`

### Missing at source (deleted upstream since snapshot) (2)

**`src/`**
- `src/bin/ext_conformance_matrix.rs`
- `src/bin/ext_conformance_report.rs`

The two binaries above were present at snapshot capture (their SHA-256 entries
remain in `TRANSPLANT_LOCKFILE.sha256`) but have since been deleted from
`/data/projects/pi_agent_rust/src/bin/`. As of 2026-05-12 the source directory
contains only `pi_legacy_capture.rs`.

## Reproducing this restore

```bash
cd /data/projects/franken_node
./transplant/restore_snapshot.sh           # exits 1 due to 2 missing source files
./transplant/verify_lockfile.sh --json     # exits 1, verdict FAIL:MISMATCH (expected)
```

`restore_snapshot.sh --force` will overwrite an existing rehydrated tree;
`--dry-run` prints the planned `cp` operations without touching the filesystem.

## Scope boundary (per bd-1qz.1)

This rehydration restores the **filesystem state** of the transplant snapshot.
It explicitly does **not**:

- Regenerate `TRANSPLANT_LOCKFILE.sha256` (the lockfile remains the audit
  baseline; regenerating would erase the divergence record).
- Add a Rust-level inventory test against `pi_agent_rust/` (deferred to a
  follow-up bead per the bd-1qz.1 investigation plan).
- Integrate any of the restored sources into the franken_node crate graph.
