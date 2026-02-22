# bd-2zl.1 Support Diagnostics Summary

## Scope
Support lane for `bd-2zl` (non-overlapping diagnostics/evidence only).

## Findings
1. `transplant/pi_agent_rust` snapshot directory is missing in current workspace.
2. `transplant/generate_lockfile.sh` exits non-zero when snapshot directory is absent.
3. `transplant/verify_lockfile.sh` exits non-zero when snapshot directory is absent.
4. Generator script embeds dynamic UTC timestamp in output header (`generated_utc`), which conflicts with byte-identical lockfile determinism unless normalized.

## Command Outcomes
- `./transplant/generate_lockfile.sh --output /tmp/bd2zl1_probe.lock` -> exit 2
- `./transplant/verify_lockfile.sh --json` -> exit 2

## Evidence Files
- `transplant_dir_listing.txt`
- `generate_lockfile.stdout`
- `generate_lockfile.stderr`
- `verify_lockfile.stdout`
- `verify_lockfile.stderr`
- `generate_lockfile_timestamp_lines.txt`
