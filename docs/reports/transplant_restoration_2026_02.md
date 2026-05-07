# Transplant Restoration Report

## Summary

| Field | Value |
|-------|-------|
| Source | `/data/projects/pi_agent_rust` |
| Destination | `transplant/pi_agent_rust/` |
| Total files restored | 369 |
| SHA256 verification | 369/369 PASS (0 FAILED) |
| Restoration date | 2026-02-20 |
| Restored by | CrimsonCrane (claude-code / opus-4.6) |
| Bead | bd-1qz |

## File Breakdown

| Category | Count | Description |
|----------|-------|-------------|
| `src/` | 25 | Extension host source modules (conformance, dispatch, validation, hostcall, trust) |
| `docs/` | 41 | Extension architecture docs, schemas, catalogs, threat models, conformance specs |
| `tests/` | 303 | Extension conformance fixtures, integration tests, stress tests, policy tests |

## Integrity Verification

All 369 files were verified against `TRANSPLANT_LOCKFILE.sha256`:
- Hash algorithm: SHA-256
- Lockfile generated: 2026-02-20T07:26:53Z
- Verification result: 369 OK, 0 FAILED

## Restoration Procedure

1. Extracted file paths from `TRANSPLANT_LOCKFILE.sha256` (369 entries)
2. Created destination directory structure under `transplant/pi_agent_rust/`
3. Copied each file from source preserving relative paths
4. Verified all SHA256 hashes match lockfile expectations
5. Generated `transplant_manifest.txt` with sorted file inventory

## Downstream Readiness

This restoration satisfies the input requirements for:
- `bd-7rt` — Generate transplant hash lockfile for tamper detection
- `bd-29q` — Add transplant re-sync + drift detection workflow
- `bd-10zx` — Foundation integration and legacy-bead convergence
- `bd-3k9t` — Implement foundation e2e scripts with structured log bundles

## Provenance

The snapshot preserves raw source paths from `pi_agent_rust` so behavior can be integrated incrementally while retaining audit traceability. The source revision is the HEAD of `/data/projects/pi_agent_rust` at lockfile generation time (2026-02-20T07:26:53Z).
