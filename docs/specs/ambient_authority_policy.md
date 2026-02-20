# Ambient Authority Policy (Section 10.15 / `bd-721z`)

This policy enforces **Hard Runtime Invariant #10: no ambient authority** in control-plane code.

## Restricted APIs

The ambient-authority gate audits `crates/franken-node/src/connector/` and `crates/franken-node/src/conformance/` for direct usage of:

- `std::net::*`
- `tokio::net::*`
- `std::process::Command`
- `tokio::process::*`
- `std::fs::*`
- `std::time::Instant`
- `std::time::SystemTime`
- `tokio::time::sleep` and `tokio::time::timeout` without `Cx`-bound context
- `tokio::spawn` outside region/capability ownership flow

## Allowlist Process

Exceptions are declared in `docs/specs/ambient_authority_allowlist.toml` under `[[exceptions]]` with:

- `id`
- `module_path`
- `ambient_api`
- `justification`
- `signer`
- `expires_on` (`YYYY-MM-DD`)
- `signature`

### Signature Rule

Signatures use a deterministic SHA-256 digest over:

```text
{module_path}\n{ambient_api}\n{justification}\n{signer}\n{expires_on}
```

Stored form:

```text
sha256:<hex-digest>
```

Unsigned, tampered, or expired entries are treated as violations.

## Enforcement Semantics

- `AMB-001`: module clean (no ambient-authority findings)
- `AMB-002`: ambient-authority violation (not allowlisted)
- `AMB-003`: allowlisted usage (valid signature + non-expired)
- `AMB-004`: invalid allowlist (expired, malformed date, or bad signature)

## Review and Escalation

1. Default action is refactor to capability-gated APIs.
2. If immediate refactor is not possible, add a bounded exception with clear justification and expiry.
3. Security/code owners review all exception additions and renewals.
4. Escalations for new ambient API classes must update this policy before allowlisting.
