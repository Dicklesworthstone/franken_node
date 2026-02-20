# bd-2yh Contract: Extension Trust-Card API + CLI Surfaces

## Scope

Define and expose deterministic trust-card state for extensions across API and CLI surfaces.

## Required Trust-Card Model

`TrustCard` includes:
- extension identity (`extension_id`, version)
- publisher identity (`publisher_id`, display name)
- certification level
- capability declarations + capability risk
- behavioral profile
- provenance summary
- revocation status
- quarantine flag
- dependency trust summary
- reputation score + trend
- user-facing risk assessment
- last-verified timestamp
- schema version + trust-card version + previous-version hash
- card hash + registry signature

## API Surface

Required route handlers in `src/api/trust_card_routes.rs`:
- `GET /trust-cards/{extension_id}` -> `get_trust_card(...)`
- `GET /trust-cards/publisher/{publisher_id}` -> `get_trust_cards_by_publisher(...)`
- `GET /trust-cards/search?query=...` -> `search_trust_cards(...)`

Required lifecycle helpers:
- `create_trust_card(...)`
- `update_trust_card(...)`
- `list_trust_cards(...)`
- `compare_trust_cards(...)`
- `compare_trust_card_versions(...)`

All list/search responses support pagination metadata.

## CLI Surface

Required command family in `src/cli.rs` + `src/main.rs`:
- `franken-node trust-card show <extension_id> [--json]`
- `franken-node trust-card export <extension_id> --json`
- `franken-node trust-card list [--publisher <publisher_id>] [--query <text>] [--page N] [--per-page N] [--json]`
- `franken-node trust-card compare <left_extension_id> <right_extension_id> [--json]`
- `franken-node trust-card diff <extension_id> <left_version> <right_version> [--json]`

CLI and API must use the same registry/model logic; no duplicate business rules.

## Versioning + Integrity Invariants

| ID | Statement |
|----|-----------|
| INV-TC-VERSION-LINK | Every mutation increments `trust_card_version` and stores the previous card hash in `previous_version_hash`. |
| INV-TC-DETERMINISTIC | Identical logical inputs produce identical card hash + signature. |
| INV-TC-SIGNATURE | Card display/export requires hash and HMAC signature verification. |
| INV-TC-DIFF | Diff output reports meaningful posture changes (certification, reputation, revocation, quarantine, capability/extension version deltas). |
| INV-TC-CACHE | Registry read path supports cache hit/miss/stale-refresh semantics with bounded TTL. |

## Structured Telemetry Events

Stable event codes:
- `TRUST_CARD_CREATED`
- `TRUST_CARD_UPDATED`
- `TRUST_CARD_REVOKED`
- `TRUST_CARD_QUERIED`
- `TRUST_CARD_COMPUTED`
- `TRUST_CARD_SERVED`
- `TRUST_CARD_CACHE_HIT`
- `TRUST_CARD_CACHE_MISS`
- `TRUST_CARD_STALE_REFRESH`
- `TRUST_CARD_DIFF_COMPUTED`

## Verification Artifacts

- Implementation: `crates/franken-node/src/supply_chain/trust_card.rs`
- API: `crates/franken-node/src/api/trust_card_routes.rs`
- CLI wiring: `crates/franken-node/src/cli.rs`, `crates/franken-node/src/main.rs`
- Verifier: `scripts/check_trust_card.py`
- Unit tests: `tests/test_check_trust_card.py`
- Evidence:
  - `artifacts/section_10_4/bd-2yh/verification_evidence.json`
  - `artifacts/section_10_4/bd-2yh/verification_summary.md`
