# Bootstrap Config Contract (`bd-n9r`)

## Goal

Provide deterministic, profile-aware configuration resolution for `franken-node` so bootstrap commands can consume one canonical config pipeline.

## Sources and Precedence

Resolution order is fixed and deterministic:

1. `defaults` (`Config::for_profile(<selected-profile>)`)
2. `profile block` (`[profiles.<selected-profile>]`)
3. `file base` (top-level sections in config file)
4. `env` (`FRANKEN_NODE_*` overrides)
5. `cli` (explicit command-line profile override)

Short form: `CLI > env > profile-block > file-base > defaults`.

## Discovery

When `--config` is omitted, discovery checks:

1. `./franken_node.toml`
2. `~/.config/franken-node/config.toml`

If neither exists, defaults are used.

## File Schema

Top-level keys:

- `profile = "strict|balanced|legacy-risky"` (optional)
- section tables:
  - `[compatibility]`
  - `[migration]`
  - `[trust]`
  - `[replay]`
  - `[registry]`
  - `[fleet]`
  - `[observability]`
  - `[remote]`
  - `[security]`
- profile overlays:
  - `[profiles.strict.*]`
  - `[profiles.balanced.*]`
  - `[profiles."legacy-risky".*]`

All section fields are optional in file overlays; omitted fields inherit from lower-precedence layers.

## Environment Overrides

Supported `FRANKEN_NODE_*` keys:

- `FRANKEN_NODE_PROFILE`
- `FRANKEN_NODE_COMPATIBILITY_MODE`
- `FRANKEN_NODE_COMPATIBILITY_EMIT_DIVERGENCE_RECEIPTS`
- `FRANKEN_NODE_COMPATIBILITY_DEFAULT_RECEIPT_TTL_SECS`
- `FRANKEN_NODE_MIGRATION_AUTOFIX`
- `FRANKEN_NODE_MIGRATION_REQUIRE_LOCKSTEP_VALIDATION`
- `FRANKEN_NODE_TRUST_RISKY_REQUIRES_FRESH_REVOCATION`
- `FRANKEN_NODE_TRUST_DANGEROUS_REQUIRES_FRESH_REVOCATION`
- `FRANKEN_NODE_TRUST_QUARANTINE_ON_HIGH_RISK`
- `FRANKEN_NODE_REPLAY_PERSIST_HIGH_SEVERITY`
- `FRANKEN_NODE_REPLAY_BUNDLE_VERSION`
- `FRANKEN_NODE_REPLAY_MAX_REPLAY_CAPSULE_FRESHNESS_SECS`
- `FRANKEN_NODE_REGISTRY_REQUIRE_SIGNATURES`
- `FRANKEN_NODE_REGISTRY_REQUIRE_PROVENANCE`
- `FRANKEN_NODE_REGISTRY_MINIMUM_ASSURANCE_LEVEL`
- `FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS`
- `FRANKEN_NODE_OBSERVABILITY_NAMESPACE`
- `FRANKEN_NODE_OBSERVABILITY_EMIT_STRUCTURED_AUDIT_EVENTS`
- `FRANKEN_NODE_REMOTE_IDEMPOTENCY_TTL_SECS`
- `FRANKEN_NODE_SECURITY_MAX_DEGRADED_DURATION_SECS`

Boolean env values accept: `true/false/1/0/yes/no/on/off`.

## Validation Rules

Resolution fails with stable diagnostics when:

- profile/mode tokens are invalid
- env values have invalid type encodings
- `registry.minimum_assurance_level` is outside `[1,5]`
- `fleet.convergence_timeout_seconds` is `0`
- `compatibility.default_receipt_ttl_secs` is `0`
- `replay.max_replay_capsule_freshness_secs` is `0`
- `replay.bundle_version` is empty
- `observability.namespace` is empty
- `remote.idempotency_ttl_secs` is `0`
- `security.max_degraded_duration_secs` is `0`

## Merge Provenance

Resolver emits merge decisions as structured entries:

- `stage`: `default | profile | file | env | cli`
- `field`: canonical path (e.g., `migration.autofix`)
- `value`: applied value

`init` and `doctor` both consume the same resolver so parsing/precedence behavior is not duplicated.
