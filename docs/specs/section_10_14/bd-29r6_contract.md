# bd-29r6: Content-Derived Deterministic Seed Derivation

## Overview

Implements domain-separated deterministic seed derivation using SHA-256 for
encoding and repair scheduling. Ensures identical `(domain, content_hash, config)`
tuples produce identical seeds across all platforms, Rust versions, and runtime
configurations.

## Module

`crates/franken-node/src/encoding/deterministic_seed.rs`

## Key Types

| Type | Purpose |
|------|---------|
| `DomainTag` | Enum of domain-separation tags (Encoding, Repair, Scheduling, Placement, Verification) |
| `ContentHash` | 32-byte SHA-256 of raw content (deriver never touches raw content) |
| `ScheduleConfig` | Versioned parameter map (BTreeMap for deterministic ordering) |
| `DeterministicSeed` | 32-byte derived seed with domain and config version metadata |
| `DeterministicSeedDeriver` | Stateful wrapper with version bump tracking |
| `VersionBumpRecord` | Emitted when config change alters derived seed |

## Derivation Algorithm

```
SHA-256(domain_prefix || 0x00 || content_hash || config_hash)
```

- `domain_prefix`: versioned string, e.g. `"franken_node.encoding.v1"`
- `0x00`: null separator preventing prefix collisions
- `content_hash`: 32-byte pre-computed hash (constant-time w.r.t. content size)
- `config_hash`: SHA-256 of version (LE u32) + sorted key-value pairs

## Invariants

| ID | Description |
|----|-------------|
| INV-SEED-DOMAIN-SEP | Different domains always produce different seeds |
| INV-SEED-STABLE | Identical inputs produce identical outputs, always |
| INV-SEED-BOUNDED | Constant-time w.r.t. content size |
| INV-SEED-NO-PLATFORM | No float, no locale, no platform-dependent behavior |

## Event Codes

| Code | Description |
|------|-------------|
| SEED_DERIVED | Seed successfully derived |
| SEED_VERSION_BUMP | Config change detected, version bump recorded |

## Acceptance Criteria

1. Domain-separated, stable derivation: identical content/config → identical seed.
2. Golden derivation vectors: 12 test cases covering all 5 domain tags.
3. Version bump artifact automatically emitted on config hash change.
4. Constant-time w.r.t. content size (operates on hash, not raw content).
5. No platform-dependent behavior (no float, no locale).
6. 47 Rust unit tests including 6 golden vector cross-checks.
