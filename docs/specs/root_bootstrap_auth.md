# Root Bootstrap Authentication Contract (bd-25nl)

## Purpose

`bootstrap_root` is the fail-closed trust gate for loading control-plane root state.
No caller should treat root pointer state as trusted unless bootstrap verification succeeds.

## API

```rust
pub fn bootstrap_root(
    dir: &Path,
    auth_config: &RootAuthConfig,
) -> Result<VerifiedRoot, BootstrapError>
```

## Inputs

- `root_pointer.json` at the canonical root pointer path.
- `root_pointer.auth.json` detached auth record containing:
  - `root_format_version`
  - `root_hash`
  - `epoch`
  - `issued_at`
  - `mac`

## Verification Steps (Fail-Closed)

1. Root pointer file exists and is readable.
2. Root pointer JSON parses to `RootPointer`.
3. Detached auth record exists and parses to `RootAuthRecord`.
4. `root_format_version` matches `RootAuthConfig.expected_format_version`.
5. Root epoch is not beyond `current_epoch + max_future_epochs`.
6. Detached `root_hash` matches SHA-256 over canonical root bytes.
7. Detached `epoch` matches parsed root epoch.
8. Detached MAC validates against the configured trust anchor.

Any failure aborts bootstrap and returns `BootstrapError`.

## Error Contract

`BootstrapError` variants:

- `RootMissing { path }`
- `RootMalformed { path, reason }`
- `RootAuthFailed { reason }`
- `RootEpochInvalid { current_epoch, root_epoch, max_allowed_epoch }`
- `RootVersionMismatch { expected, actual }`

Error codes:

- `ROOT_BOOTSTRAP_MISSING`
- `ROOT_BOOTSTRAP_MALFORMED`
- `ROOT_BOOTSTRAP_AUTH_FAILED`
- `ROOT_BOOTSTRAP_EPOCH_INVALID`
- `ROOT_BOOTSTRAP_VERSION_MISMATCH`

## Security Properties

- Fail-closed on missing/corrupt/unauthenticated root state.
- Epoch-future rejection prevents bootstrap from accepting ahead-of-frontier roots.
- Version check blocks unknown root format versions.
- Diagnostic errors include expected/actual context without leaking key material.

## Logging Guidance

Recommended structured events:

- `ROOT_BOOTSTRAP_START`
- `ROOT_BOOTSTRAP_SUCCESS`
- `ROOT_BOOTSTRAP_FAILED`

Each log record should include `trace_id`, root path, and `BootstrapError` code.
