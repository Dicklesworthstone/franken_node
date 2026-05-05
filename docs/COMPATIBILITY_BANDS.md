# Compatibility Bands

> Defines the four compatibility bands for classifying Node/Bun API surface areas,
> with policy defaults governing divergence handling per band and compatibility mode.

**Authority**: [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
**Related**: [ADR-001: Hybrid Baseline Strategy](adr/ADR-001-hybrid-baseline-strategy.md)

---

## 1. Overview

Every Node/Bun API surface that franken_node implements is classified into one of four **compatibility bands**. Bands determine how divergences are handled, what testing coverage is required, and whether divergences can block releases.

## 2. Band Definitions

### 2.1 `core` — Foundation APIs

**Priority**: Highest
**Policy Default**: Strict parity required; any divergence blocks release.

Foundation APIs that virtually all Node.js/Bun applications depend on. These must match reference runtime behavior exactly, as measured by the L1 lockstep oracle.

**Example APIs**: `fs` (read/write/stat), `path`, `process` (env, argv, exit), `Buffer`, `EventEmitter`, `stream` (Readable, Writable, Transform, Duplex), `module` (require, import), `console`, `util.promisify`.

**Divergence handling**:
- All divergences produce structured receipts with signed rationale
- Unresolved divergences block release in all compatibility modes
- Oracle coverage: 100% of core fixtures must execute

### 2.2 `high-value` — Frequently-Used Patterns

**Priority**: High
**Policy Default**: >= 95% pass rate target; divergences logged with receipts.

APIs and patterns used by the majority of production Node.js applications. These are the strategic wedge for migration — high compatibility here drives adoption.

**Example APIs**: `http`/`https` (client + server), `crypto` (hashing, HMAC, symmetric encryption), `child_process`, `timers` (setTimeout, setInterval, setImmediate), `url` (URL, URLSearchParams), `dns`, `net`, `zlib`, `os`.

**Divergence handling**:
- Divergences produce structured receipts
- Unresolved divergences block release in `strict` mode
- In `balanced` mode: warn + receipt, no release block
- Oracle coverage: >= 95% of high-value fixtures must pass

### 2.3 `edge` — Corner Cases and Platform Quirks

**Priority**: Medium
**Policy Default**: Best-effort; divergences logged, no release block.

Undocumented behaviors, platform-specific quirks, and corner cases that few applications depend on. These are tracked for completeness but do not gate releases.

**Example APIs**: Obscure `fs` flag combinations, platform-specific `process` signals, legacy encoding behaviors, deprecated API compatibility, undocumented EventEmitter edge cases, `vm` module internals.

**Divergence handling**:
- Divergences logged with receipts for audit trail
- No release block in any mode
- Tracked in divergence ledger for future prioritization
- Oracle coverage: best-effort, no minimum threshold

### 2.4 `unsafe` — Dangerous Behaviors

**Priority**: Lowest (disabled by default)
**Policy Default**: Blocked; requires explicit policy opt-in.

Behaviors that bypass security controls, allow unrestricted native access, or undermine the trust-native architecture. These exist for legacy compatibility only and are disabled by default.

**Example APIs**: `eval()`/`Function()` with dynamic code, `vm.runInNewContext` without sandboxing, unrestricted `child_process.exec`, `process.binding()`, native addon loading without permission checks, `--allow-all` flag patterns.

**Divergence handling**:
- Blocked in `strict` and `balanced` modes (no execution)
- In `legacy-risky` mode: gated behind explicit policy declaration + warning
- Every unsafe invocation produces audit receipt regardless of mode
- Oracle coverage: N/A (unsafe behaviors are not oracle targets)

## 3. Compatibility Modes

Three modes control how divergences are handled across all bands:

### 3.1 `strict`

Maximum fidelity. Errors on any divergence in core or high-value bands. Unsafe behaviors blocked.

| Band | Behavior |
|------|----------|
| `core` | Error on divergence |
| `high-value` | Error on divergence |
| `edge` | Warn + receipt |
| `unsafe` | Blocked |

### 3.2 `balanced` (default)

Production default. Errors on core divergences, warns on high-value, logs edge cases. Unsafe blocked.

| Band | Behavior |
|------|----------|
| `core` | Error on divergence |
| `high-value` | Warn + receipt |
| `edge` | Log + receipt |
| `unsafe` | Blocked |

### 3.3 `legacy-risky`

Maximum compatibility. Same as balanced but permits unsafe behaviors behind policy gates.

| Band | Behavior |
|------|----------|
| `core` | Error on divergence |
| `high-value` | Warn + receipt |
| `edge` | Log + receipt |
| `unsafe` | Warn + policy gate |

## 4. Configuration

```toml
[compatibility]
mode = "balanced"              # strict | balanced | legacy-risky
emit_divergence_receipts = true
```

Band classification is not configurable at runtime — it is determined by the API surface definition and maintained in the compatibility behavior registry.

## 5. Oracle Integration

- **L1 Product Oracle**: Validates core and high-value bands against Node/Bun reference outputs
- **L2 Engine-Boundary Oracle**: Validates engine trust boundaries are preserved across all bands
- Both oracles must pass for release gating; neither replaces the other

## 6. References

- [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2 — Compatibility Core
- [ADR-001: Hybrid Baseline Strategy](adr/ADR-001-hybrid-baseline-strategy.md) — No Bun-first clone
- [PRODUCT_CHARTER.md](PRODUCT_CHARTER.md) — >= 95% compatibility target
- [IMPLEMENTATION_GOVERNANCE.md](IMPLEMENTATION_GOVERNANCE.md) — Spec-first extraction discipline
