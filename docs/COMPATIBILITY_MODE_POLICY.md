# Compatibility Mode Selection Policy

> Defines the three runtime compatibility modes and their enforcement rules.

**Authority**: [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
**Related**: [COMPATIBILITY_BANDS.md](COMPATIBILITY_BANDS.md)

---

## 1. Overview

franken_node supports three compatibility modes that control how behavioral divergences from Node.js/Bun are handled at runtime. The mode is selected via configuration and applies globally to all API compatibility behavior.

## 2. Mode Definitions

### 2.1 `strict` Mode

Maximum fidelity mode for applications requiring exact behavioral parity.

| Band | Behavior |
|------|----------|
| `core` | Error on divergence — execution halts with structured error |
| `high-value` | Error on divergence — execution halts with structured error |
| `edge` | Warn + emit divergence receipt |
| `unsafe` | Blocked — returns policy-gate error |

**Use case**: Test suites, conformance validation, migration verification.

### 2.2 `balanced` Mode (Default)

Production default balancing compatibility with trust-native guarantees.

| Band | Behavior |
|------|----------|
| `core` | Error on divergence — execution halts with structured error |
| `high-value` | Warn + emit divergence receipt — execution continues |
| `edge` | Log + emit divergence receipt — silent to application |
| `unsafe` | Blocked — returns policy-gate error |

**Use case**: Production deployments, general-purpose applications.

### 2.3 `legacy-risky` Mode

Maximum compatibility mode that permits unsafe behaviors behind explicit policy gates.

| Band | Behavior |
|------|----------|
| `core` | Error on divergence — execution halts with structured error |
| `high-value` | Warn + emit divergence receipt — execution continues |
| `edge` | Log + emit divergence receipt — silent to application |
| `unsafe` | Warn + policy gate — requires explicit `[compatibility.unsafe_opt_in]` in config |

**Use case**: Legacy application migration where unsafe behaviors are temporarily required.

**Opt-in requirement**: Unsafe behaviors in `legacy-risky` mode require:
```toml
[compatibility]
mode = "legacy-risky"

[compatibility.unsafe_opt_in]
process_binding = true
vm_unrestricted = true
# Each unsafe behavior must be individually enabled
```

## 3. Default Mode

The default compatibility mode is **`balanced`**. This is the mode used when no explicit configuration is provided. It provides strong compatibility for core and high-value APIs while maintaining the trust-native security posture.

## 4. Configuration

```toml
[compatibility]
mode = "balanced"              # strict | balanced | legacy-risky
emit_divergence_receipts = true  # whether to emit receipts (default: true)
```

Mode can be set via:
1. Configuration file (`franken_node.toml`)
2. Environment variable: `FRANKEN_COMPAT_MODE=strict`
3. CLI flag: `--compat-mode=strict`

Priority order: CLI flag > environment variable > config file > default (balanced).

## 5. Enforcement Rules

1. **Core band divergences always error** regardless of mode. Core is the non-negotiable compatibility floor.
2. **Unsafe behaviors are blocked** in `strict` and `balanced` modes. No configuration can override this.
3. **In `legacy-risky` mode**, unsafe behaviors require per-behavior opt-in in the configuration. A blanket `mode = "legacy-risky"` alone does not enable unsafe behaviors.
4. **All divergences produce receipts** when `emit_divergence_receipts` is true (default). Receipts are structured JSON entries in the divergence log.
5. **Mode changes at runtime are not permitted**. The mode is fixed at startup from configuration.

## 6. References

- [COMPATIBILITY_BANDS.md](COMPATIBILITY_BANDS.md) — Band definitions
- [DIVERGENCE_LEDGER.json](DIVERGENCE_LEDGER.json) — Known divergences
- [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
