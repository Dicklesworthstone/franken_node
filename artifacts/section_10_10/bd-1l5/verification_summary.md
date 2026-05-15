# bd-1l5: Canonical Product Trust Object IDs with Domain Separation

**Section:** 10.10 | **Verdict:** PASS | **Date:** 2026-05-15

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 108 | 108 |
| Rust unit tests | 80 | 80 |
| Evidence analysis checks | 21 | 21 |

## Implementation

**File:** `crates/franken-node/src/connector/trust_object_id.rs`

### Core Types (7 structs/enums)
- `DomainPrefix` — Extension, TrustCard, Receipt, PolicyCheckpoint, MigrationArtifact, VerifierClaim
- `DerivationMode` — ContentAddressed, ContextAddressed
- `TrustObjectId` — domain-separated ID with digest, derivation mode, epoch/sequence
- `IdRegistry` — registry of valid domain prefixes with version metadata
- `DomainRegistryEntry` — registry entry with description, prefix, algorithm
- `IdError` — InvalidPrefix, MalformedDigest, InvalidFormat, UnknownDomain
- `IdEvent` — structured audit event for ID operations

### Key API Methods
- `derive_content_addressed(domain, data)` — content-addressed ID: `<prefix>sha256:<digest>`
- `derive_context_addressed(domain, epoch, seq, data)` — context-addressed: `<prefix><epoch>:<seq>:<digest>`
- `parse(s)` — parse canonical string form back to TrustObjectId
- `validate(s)` — check if string is well-formed trust object ID
- `full_form()` — canonical string representation
- `short_form()` — `<prefix><first_8_hex>` for logging
- `sha256_digest(data)` — compute SHA-256 hex digest
- `canonical_bytes(data)` — deterministic serialization
- `derive_trust_object_id_events(inputs)` — derive auditable ID events from caller-supplied trust objects

### Domain Prefixes (6)
| Prefix | Domain | Description |
|--------|--------|-------------|
| `ext:` | Extension | Extension trust objects |
| `tcard:` | TrustCard | Trust card objects |
| `rcpt:` | Receipt | Receipt objects |
| `pchk:` | PolicyCheckpoint | Policy checkpoint objects |
| `migr:` | MigrationArtifact | Migration artifact objects |
| `vclaim:` | VerifierClaim | Verifier claim objects |

### Event Codes (2)
| Code | Description |
|------|-------------|
| TOI-001 | Trust object ID derived |
| TOI-002 | Trust object ID validation failed |

### Error Codes (4)
- ERR_TOI_INVALID_PREFIX, ERR_TOI_MALFORMED_DIGEST
- ERR_TOI_INVALID_FORMAT, ERR_TOI_UNKNOWN_DOMAIN

### Invariants (4)
- **INV-TOI-PREFIX**: Every ID has a valid domain prefix
- **INV-TOI-DETERMINISTIC**: Same inputs always produce the same ID
- **INV-TOI-COLLISION**: Cross-domain collisions structurally impossible
- **INV-TOI-DIGEST**: SHA-256 with >= 128 bits collision resistance

## Verification Commands

```bash
python3 scripts/check_trust_object_ids.py --json    # 108/108 PASS
python3 -m unittest tests/test_check_trust_object_ids.py  # Python unit tests
```
