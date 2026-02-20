# bd-okqy: L1/L2/L3 Tiered Trust Artifact Storage

## Scope

Tiered storage abstraction for trust artifacts with explicit source-of-truth
designation per object class. Three tiers with distinct authority levels,
latency profiles, and recovery paths.

## Tiers

| Tier | Authority | Latency | Purpose |
|------|-----------|---------|---------|
| L1 Local | 3 (highest) | Hot | Working set for immediate control-plane decisions |
| L2 Warm | 2 | Moderate | Recently-active artifacts for rapid recovery |
| L3 Archive | 1 (lowest) | Cold | Durable long-term copies for audit and DR |

## Authority Map

Each object class (bd-2573) maps to exactly one authoritative tier via
`AuthorityMap`. The mapping is **immutable** after initialization.

Default assignments:

| Object Class | Authoritative Tier | Rationale |
|-------------|-------------------|-----------|
| critical_marker | L1 Local | Immediate control-plane access |
| trust_receipt | L2 Warm | Rapid recovery for audit |
| replay_bundle | L3 Archive | Durable long-term storage |
| telemetry_artifact | L2 Warm | On-demand observability |

Runtime mutation of the authority map returns `ERR_AUTHORITY_MAP_IMMUTABLE`.

## Operations

Each tier exposes:

- `store(artifact)` → ArtifactId
- `retrieve(artifact_id)` → Result<TrustArtifact>
- `evict(artifact_id)` → Result<TrustArtifact>
- `authority_level()` → AuthorityLevel

### Eviction Preconditions

- L1 eviction requires artifact exists in L2 or L3 (retrievability proof)
- L2 eviction requires artifact exists in L3
- L3 eviction is unrestricted (permanent deletion)

Violation returns `ERR_EVICT_REQUIRES_RETRIEVABILITY`.

## Recovery Path

`recover_tier(target_tier, artifact_id)` reconstructs a derived tier's content
from a higher-authority source tier.

Valid directions:

- L2 → L1 (warm to hot)
- L3 → L1 (archive to hot)
- L3 → L2 (archive to warm)

When multiple sources exist, the highest-authority source is preferred
(L2 over L3 for L1 recovery).

Recovery into L3 returns `ERR_RECOVERY_DIRECTION_INVALID`.

## Invariants

| ID | Statement |
|----|-----------|
| INV-TIER-AUTHORITY | Each object class maps to exactly one authoritative tier |
| INV-TIER-IMMUTABLE | Authority map is immutable after initialization |
| INV-TIER-RECOVERY | Recovery reconstructs derived tier content from authoritative tier |
| INV-TIER-ORDERED | Authority levels are strictly ordered L1 > L2 > L3 |

## Event Codes

| Code | Trigger |
|------|---------|
| TS_TIER_INITIALIZED | Tier startup |
| TS_STORE_COMPLETE | Artifact stored |
| TS_RETRIEVE_COMPLETE | Artifact retrieved |
| TS_EVICT_COMPLETE | Artifact evicted |
| TS_RECOVERY_START | Recovery path initiated |
| TS_RECOVERY_COMPLETE | Recovery path completed |
| TS_AUTHORITY_MAP_VIOLATION | Runtime mutation attempt on authority map |

## Error Codes

| Code | Condition |
|------|-----------|
| ERR_AUTHORITY_MAP_IMMUTABLE | Authority map mutation attempted after init |
| ERR_ARTIFACT_NOT_FOUND | Artifact not found in specified tier |
| ERR_RECOVERY_SOURCE_MISSING | No source artifact found for recovery |
| ERR_RECOVERY_DIRECTION_INVALID | Recovery direction invalid (e.g., into L3) |
| ERR_EVICT_REQUIRES_RETRIEVABILITY | Eviction without retrievability proof |

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/connector/tiered_trust_storage.rs` |
| Spec contract | `docs/specs/section_10_14/bd-okqy_contract.md` |
| Authority map snapshot | `artifacts/10.14/tiered_storage_authority_map.json` |
| Verification script | `scripts/check_tiered_trust_storage.py` |
| Python unit tests | `tests/test_check_tiered_trust_storage.py` |
| Verification evidence | `artifacts/section_10_14/bd-okqy/verification_evidence.json` |
| Verification summary | `artifacts/section_10_14/bd-okqy/verification_summary.md` |
