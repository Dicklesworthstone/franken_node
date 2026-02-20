# bd-v97o: Authenticated Control Channel

## Purpose

Authenticated control channel with per-direction sequence monotonicity and replay-window checks. Prevents replay attacks and out-of-order processing.

## Invariants

- **INV-ACC-AUTHENTICATED**: Every control channel message must pass authentication before processing.
- **INV-ACC-MONOTONIC**: Sequence numbers must be strictly monotonically increasing per direction (send/receive).
- **INV-ACC-REPLAY-WINDOW**: Messages with sequence numbers inside the replay window are rejected.
- **INV-ACC-AUDITABLE**: Every authentication and sequence check emits a structured audit record.

## Types

### ChannelConfig

Config: replay_window_size, require_auth.

### ChannelMessage

Message: message_id, direction (Send/Receive), sequence_number, auth_token, payload_hash.

### ChannelState

Per-direction state: last_sequence_send, last_sequence_recv, replay_window bitmap.

### AuthCheckResult

Result: message_id, authenticated, sequence_valid, replay_clean, verdict.

## Error Codes

- `ACC_AUTH_FAILED` — authentication check failed
- `ACC_SEQUENCE_REGRESS` — sequence number not monotonically increasing
- `ACC_REPLAY_DETECTED` — message sequence in replay window
- `ACC_INVALID_CONFIG` — channel configuration invalid
- `ACC_CHANNEL_CLOSED` — channel is closed
