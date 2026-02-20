# bd-ck2h — Conformance Profile Matrix

## Overview

Defines an MVP vs Full conformance profile matrix.  Each profile lists the
required capabilities a connector must demonstrate.  A profile evaluator
compares measured test results against the matrix and produces publication
metadata.  Unsupported claims are blocked — a connector cannot claim a profile
it has not fully passed.

## Profiles

| Profile | Required Capabilities |
|---------|----------------------|
| MVP | serialization, auth, lifecycle, fencing, frame_parsing |
| Full | MVP + crdt, lease_coordination, quarantine, retention, anti_amplification, trace_correlation, telemetry, error_codes |

## Invariants

- **INV-CPM-MATRIX** — The profile matrix is defined with explicit required
  capabilities per profile; unknown profiles are rejected.
- **INV-CPM-MEASURED** — Profile claims are evaluated against measured test
  results, not declarations; missing results for a required capability fail
  the check.
- **INV-CPM-BLOCKED** — A connector cannot publish a claim for a profile if
  any required capability has not passed; the gate returns a blocking verdict.
- **INV-CPM-METADATA** — Successful profile evaluation produces machine-readable
  publication metadata with profile name, version, and per-capability pass/fail.

## Types

- `Profile` — MVP / Full
- `CapabilityResult` — capability name, passed bool, details
- `ProfileMatrix` — maps profiles to required capability lists
- `ClaimEvaluation` — profile, per-capability results, verdict, metadata
- `ProfileError` — error codes for contract violations

## Error Codes

| Code | Meaning |
|------|---------|
| `CPM_UNKNOWN_PROFILE` | Requested profile not in matrix |
| `CPM_MISSING_RESULT` | Required capability has no test result |
| `CPM_CAPABILITY_FAILED` | Required capability test did not pass |
| `CPM_CLAIM_BLOCKED` | Cannot publish — profile not fully satisfied |
| `CPM_INVALID_MATRIX` | Matrix definition has errors |
