# bd-oty: Session-Authenticated Control Channel Integration

**Section:** 10.10 | **Verdict:** PASS | **Date:** 2026-05-06

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 108 | 108 |
| Python unit tests (pytest) | 30 | 30 |
| Rust unit tests present | 146 | 146 |
| Real Rust evidence checks | 7 | 7 |
| Synthetic lifecycle checks | 0 | 0 |

## Implementation

**File:** `crates/franken-node/src/api/session_auth.rs`

### Core Types (8 structs/enums)
- `SessionState` -- Establishing, Active, Terminating, Terminated
- `SessionConfig` -- replay_window, max_sessions, session_timeout_ms
- `AuthenticatedSession` -- 10-field session with identity, keys, sequence state
- `SessionManager` -- stateful lifecycle manager with sequence enforcement
- `AuthenticatedMessage` -- session-bound message with sequence and signature
- `MessageDirection` -- Send, Receive (maps from ControlChannel Direction)
- `SessionEvent` -- structured audit event with trace_id
- `SessionError` -- typed errors with stable error codes

### Key API Methods
- `establish_session()` -- create and activate a new session (SCC-001)
- `process_message()` -- verify and accept an authenticated message (SCC-002/SCC-003)
- `terminate_session()` -- terminate session, reject further messages (SCC-004)
- `validate_key_roles()` -- verify Encryption/Signing role separation
- `demo_session_lifecycle()` -- end-to-end strict monotonicity demo
- `demo_windowed_replay()` -- windowed replay detection demo

### Upstream Integration
- `connector::control_channel::Direction` -- message direction mapping (bd-v97o)
- `control_plane::key_role_separation::KeyRole` -- role-based key binding (bd-364)

### Event Codes (4)
| Code | Description |
|------|-------------|
| SCC-001 | Session established |
| SCC-002 | Authenticated message accepted |
| SCC-003 | Message rejected |
| SCC-004 | Session terminated |

### Error Codes (6)
| Code | Description |
|------|-------------|
| ERR_SCC_NO_SESSION | No active session |
| ERR_SCC_SEQUENCE_VIOLATION | Sequence monotonicity violated |
| ERR_SCC_SESSION_TERMINATED | Terminated session used |
| ERR_SCC_ROLE_MISMATCH | Wrong key role |
| ERR_SCC_AUTH_FAILED | Authentication failed |
| ERR_SCC_MAX_SESSIONS | Concurrent session limit reached |

### Invariants (4)
- **INV-SCC-SESSION-AUTH**: Every control message requires active session
- **INV-SCC-MONOTONIC**: Per-direction sequence numbers strictly monotonic
- **INV-SCC-ROLE-KEYS**: Encryption key for exchange, Signing key for auth
- **INV-SCC-TERMINATED**: Terminated sessions reject all messages

## Acceptance Criteria

| Criterion | Status |
|-----------|--------|
| Every control message requires active session | PASS |
| Per-direction sequence monotonicity enforced | PASS |
| Replay window configurable (default=0) | PASS |
| Role key separation (Encryption + Signing) | PASS |
| Terminated sessions reject all messages | PASS |
| Concurrent session limit enforced | PASS |
| All events traced with trace_id + session_id | PASS |
| Unit tests cover lifecycle, sequence, replay, keys | PASS |

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_10/bd-oty_contract.md` |
| Policy document | `docs/policy/session_authenticated_control.md` |
| Implementation | `crates/franken-node/src/api/session_auth.rs` |
| Verification script | `scripts/check_session_auth.py` |
| Unit tests | `tests/test_check_session_auth.py` |
| Evidence JSON | `artifacts/section_10_10/bd-oty/verification_evidence.json` |
| This summary | `artifacts/section_10_10/bd-oty/verification_summary.md` |

## Gap Closures

| Bead | Description | Status |
|------|-------------|--------|
| bd-ac8j | Mutual-authenticated capability sessions (HMAC transcript binding) | CLOSED |

## Verification Commands

```bash
python3 scripts/check_session_auth.py --json          # 108/108 PASS
python3 scripts/check_session_auth.py --self-test     # 108/108 PASS
python3 -m pytest tests/test_check_session_auth.py -q # 30 passed
python3 -m py_compile scripts/check_session_auth.py tests/test_check_session_auth.py
```
