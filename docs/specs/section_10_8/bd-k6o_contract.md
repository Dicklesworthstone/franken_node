# bd-k6o -- Deterministic Safe-Mode Startup and Operation Flags

## Overview

Section 10.8 (Operational Readiness) requires that franken_node provide a
first-class safe-mode operating state with deterministic entry conditions,
explicit capability restrictions, and a verified exit path back to normal
operation.  When trust state is compromised, crash loops occur, or epoch
mismatches are detected, the node must fall back to a well-defined reduced-
functionality posture that maximizes safety while preserving basic operability.

Safe mode is **deterministic**: given the same flags, environment variables,
and configuration, the node must enter the identical safe-mode state every
time -- no randomness, no race conditions, no platform-dependent variance.

## Entry Triggers

Safe mode activates through four runtime paths, evaluated in strict precedence
order:

| Priority | Trigger | Mechanism |
|----------|---------|-----------|
| 1 | Explicit runtime flag | `--safe-mode` parsed by `OperationFlags` |
| 2 | Environment variable | `FRANKEN_SAFE_MODE=1` |
| 3 | Configuration field | `safe_mode: true` in config |
| 4 | Automatic detection | Trust corruption, crash loop (3+ in 60s), or epoch mismatch |

When multiple triggers fire simultaneously, the highest-priority trigger is
recorded as the canonical entry reason.  All active triggers are logged.

## Operation Flags

These flags are currently modeled by `runtime::safe_mode::OperationFlags` for
deployment integrations and tests. The top-level `franken-node` CLI does not yet
ship a standalone `safe-mode` subcommand or global safe-mode startup flag.

| Flag | Effect | Combinable |
|------|--------|------------|
| `--safe-mode` | Activate safe-mode startup sequence | Yes (with all) |
| `--degraded` | Enter degraded-capability mode | Yes |
| `--read-only` | Prohibit all write operations | Yes |
| `--no-network` | Disable all outbound network access | Yes |

### Flag Precedence and Conflicts

- `--safe-mode` implies `--read-only` for trust ledger writes (unless operator override present).
- `--no-network` combined with `--degraded` is valid: node runs with reduced capabilities and no outbound traffic.
- No flag combination is invalid; however, `--safe-mode` + `--degraded` emits SMO-003 advisory (redundant: safe-mode already restricts capabilities).

## Capability Restrictions

In safe mode, the following restrictions apply:

| Capability | Normal Mode | Safe Mode |
|------------|-------------|-----------|
| Extension loading | Allowed per policy | Suspended (non-essential) |
| Network listeners | All configured | Health + admin only |
| Trust delegations | Per policy rules | Blocked |
| Trust ledger writes | Allowed | Requires explicit operator confirmation |
| Outbound network | Allowed | Health checks only |
| Scheduled tasks | Enabled | Suspended |

## Trust Re-Verification

On safe-mode entry, the node performs a full trust state verification:

1. Load current trust state from persistent storage.
2. Replay evidence ledger entries and verify consistency.
3. Detect any inconsistencies (missing entries, hash mismatches, expired epochs).
4. Persist a **SafeModeEntryReceipt** with: timestamp, entry reason, trust state
   hash, inconsistency list, and pass/fail status.
5. Log all inconsistencies as incidents for operator review.

## Logging

All operations in safe mode are logged at TRACE level with full context:
- Every decision point (capability check, trust query, policy evaluation).
- Every skipped capability with reason.
- Every trust check result with evidence hash.
- Target: at least 3x more verbose than normal mode for equivalent operations.

## Exit Protocol

Leaving safe mode requires explicit operator action through the deployment
integration that owns `SafeModeController` state (never automatic):

1. Operator requests exit through the embedding/control-plane integration.
2. Pre-exit verification: trust state consistent, no unresolved incidents,
   evidence ledger intact.
3. Operator acknowledges transition via confirmation flag or interactive prompt.
4. Exit is logged as an auditable event with operator identity and timestamp.
5. All suspended capabilities are restored in deterministic order.

## Status Reporting

`SafeModeController::status(...)` returns `SafeModeStatus`, which deployment
integrations can serialize as structured JSON:

```json
{
  "safe_mode_active": true,
  "entry_reason": "explicit_flag",
  "entry_timestamp": "2026-02-20T10:30:00Z",
  "duration_seconds": 3600,
  "suspended_capabilities": [
    "extension_loading",
    "trust_delegations",
    "scheduled_tasks"
  ],
  "trust_state_hash": "sha256:abc123...",
  "unresolved_incidents": 0,
  "active_flags": ["--safe-mode", "--read-only"]
}
```

## Event Codes

| Code | Trigger | Severity |
|------|---------|----------|
| SMO-001 | Safe-mode activated (any trigger) | INFO |
| SMO-002 | Capability restricted due to safe-mode policy | WARN |
| SMO-003 | Flag conflict or redundancy detected | WARN |
| SMO-004 | Degraded state entered (automatic trigger) | WARN |

## Invariants

- **INV-SMO-DETERMINISTIC** -- Given identical flags, environment variables, and
  configuration, safe-mode entry produces the same capability set, the same
  logging level, and the same trust re-verification sequence.  No platform-
  dependent variance.  No randomness.

- **INV-SMO-RESTRICTED** -- In safe mode, non-essential extensions are never
  loaded, trust delegations are never issued, and trust ledger writes require
  explicit operator confirmation.  Attempting a restricted operation returns
  a structured error with recovery hint.

- **INV-SMO-FLAGPARSE** -- All operation flags (`--safe-mode`, `--degraded`,
  `--read-only`, `--no-network`) are parsed deterministically.  Unknown flags
  produce a structured error.  Flag precedence is documented and tested.

- **INV-SMO-RECOVERY** -- Exiting safe mode requires explicit operator action.
  The exit protocol verifies trust state consistency, confirms no unresolved
  incidents, and logs the transition as an auditable event.  Automatic exit is
  never possible.

## Determinism Requirements

1. **Flag parsing**: identical command-line arguments produce identical internal state.
2. **Capability restriction**: the set of restricted capabilities is a pure function of the active flags.
3. **Trust re-verification**: given the same trust state and evidence ledger, re-verification produces the same receipt.
4. **Logging**: log output is structurally identical for identical inputs (timestamps may differ).
5. **Exit preconditions**: the exit checklist is evaluated deterministically with no external dependencies beyond trust state and incident list.

## Drill Testing

Each automatic trigger condition must have a dedicated drill test:

- **Trust corruption drill**: Inject inconsistent trust state, verify safe-mode entry.
- **Crash loop drill**: Simulate 3+ crashes within 60 seconds, verify safe-mode entry.
- **Epoch mismatch drill**: Inject mismatched epoch, verify safe-mode entry.

## Dependencies

- Trust state model (`state_model.rs`, `fencing.rs`) for corruption detection.
- Health gate infrastructure (`health_gate.rs`) for safe-mode health endpoint integrations.
- Runtime operation-flag parsing in `safe_mode.rs`; standalone CLI/API operator surfaces are follow-on work.
- Config plumbing for deployments that map `safe_mode` config into `SafeModeConfig`.
- Crash loop detector (`runtime/crash_loop_detector.rs`) for crash-loop trigger.

## Acceptance Criteria

1. `--safe-mode` runtime flag, `FRANKEN_SAFE_MODE=1` env var, and `safe_mode: true` config all deterministically map to safe-mode entry reasons in the runtime model.
2. Automatic safe-mode activation triggers on trust state corruption, crash loop detection (configurable threshold, default 3 crashes in 60 seconds), and epoch mismatch -- each trigger path has a dedicated test.
3. In safe mode, non-essential extensions are not loaded; attempting to load one returns a structured error with recovery hint.
4. Trust state re-verification runs on safe-mode entry and produces a persisted receipt with pass/fail status and details of any inconsistencies found.
5. All safe-mode operations are logged at TRACE level; log output in safe mode is at least 3x more verbose than normal mode for equivalent operations.
6. Exiting safe mode requires explicit operator action and passes a pre-exit verification checklist; automatic exit is not possible.
7. `SafeModeStatus` serializes structured JSON with entry reason, duration, and suspended capability list; a standalone CLI/API status surface is follow-on work.
8. A drill test simulates each automatic trigger condition and verifies correct safe-mode entry and behavior.
