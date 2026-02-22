---
schema_version: staking-v1.0
bead_id: bd-26mk
section: "10.17"
title: "Security Staking and Slashing Framework for Publisher Trust Governance"
---

# bd-26mk: Security Staking and Slashing Framework for Publisher Trust Governance

## Summary

Implements a deterministic staking and slashing framework that governs publisher
trust within the franken_node ecosystem. High-risk capabilities require publishers
to post security stakes that are subject to slashing upon validated malicious
behaviour. The framework provides a complete appeal/audit trail to ensure
accountability and prevent arbitrary punishment.

## Stake Lifecycle

```
deposit_stake() -> StakeId
  |
  +-- active()      -> ACTIVE       (capability gates satisfied)
  |
  +-- slash()       -> SLASHED      (malicious behaviour validated)
  |     |
  |     +-- appeal()    -> UNDER_APPEAL (publisher contests slash)
  |     |     |
  |     |     +-- resolve_appeal(upheld)    -> SLASHED
  |     |     +-- resolve_appeal(reversed)  -> ACTIVE (stake restored)
  |
  +-- withdraw()    -> WITHDRAWN    (publisher exits, no pending obligations)
  |
  +-- (expired)     -> EXPIRED      (stake period ended, auto-release eligible)
```

### Valid State Transitions

| From | To | Trigger |
|------|----|---------|
| ACTIVE | SLASHED | Validated malicious behaviour |
| ACTIVE | WITHDRAWN | Voluntary withdrawal (no pending obligations) |
| ACTIVE | EXPIRED | Stake period elapsed |
| SLASHED | UNDER_APPEAL | Publisher files appeal |
| UNDER_APPEAL | SLASHED | Appeal upheld (denied) |
| UNDER_APPEAL | ACTIVE | Appeal reversed (granted) |

## Stake Policy

The `StakePolicy` configures thresholds per capability risk tier:

| Risk Tier | Minimum Stake | Slash Fraction | Cooldown Period | Appeal Window |
|-----------|--------------|----------------|-----------------|---------------|
| Critical | 1000 units | 100% (total) | 72 hours | 48 hours |
| High | 500 units | 50% | 48 hours | 36 hours |
| Medium | 100 units | 25% | 24 hours | 24 hours |
| Low | 10 units | 10% | 12 hours | 12 hours |

## Core Types

- **StakeId**: Unique identifier for a security stake (u64 newtype)
- **StakeRecord**: Full record of a stake: id, publisher, amount, state, timestamps
- **StakeState**: Enum of lifecycle states: Active, Slashed, UnderAppeal, Withdrawn, Expired
- **StakePolicy**: Per-risk-tier configuration for minimums, fractions, cooldowns
- **SlashEvent**: Record of a slashing action with evidence, amount, timestamp
- **AppealRecord**: Record of an appeal: id, stake_id, reason, outcome, timestamps
- **AppealOutcome**: Enum: Upheld, Reversed, Pending
- **RiskTier**: Enum: Critical, High, Medium, Low
- **TrustGovernanceState**: Top-level state holding all stakes, events, appeals
- **SlashEvidence**: Evidence bundle attached to a slash event
- **StakingAuditEntry**: Timestamped audit log entry for any staking operation
- **CapabilityStakeGate**: Gate that checks stake sufficiency before capability activation

## Event Codes

| Code | Description |
|------|-------------|
| STAKE-001 | Stake deposited successfully |
| STAKE-002 | Stake slashed due to validated malicious behaviour |
| STAKE-003 | Appeal filed against slash decision |
| STAKE-004 | Appeal resolved (upheld or reversed) |
| STAKE-005 | Stake withdrawn by publisher |
| STAKE-006 | Stake expired and released |
| STAKE-007 | Capability gate checked against stake |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_STAKE_INSUFFICIENT | Deposited stake below minimum for risk tier |
| ERR_STAKE_NOT_FOUND | Referenced stake ID does not exist |
| ERR_STAKE_ALREADY_SLASHED | Attempt to slash an already-slashed stake |
| ERR_STAKE_WITHDRAWAL_BLOCKED | Withdrawal blocked due to pending obligations |
| ERR_STAKE_APPEAL_EXPIRED | Appeal filed after appeal window closed |
| ERR_STAKE_INVALID_TRANSITION | Invalid state transition attempted |
| ERR_STAKE_DUPLICATE_APPEAL | Duplicate appeal for same slash event |

## Invariants

| ID | Description |
|----|-------------|
| INV-STAKE-MINIMUM | Every active stake meets or exceeds the minimum for its risk tier |
| INV-STAKE-SLASH-DETERMINISTIC | Slashing is deterministic: same evidence + policy = same outcome |
| INV-STAKE-APPEAL-WINDOW | Appeals are only accepted within the configured appeal window |
| INV-STAKE-AUDIT-COMPLETE | Every state transition produces an audit entry |
| INV-STAKE-NO-DOUBLE-SLASH | A stake cannot be slashed twice for the same evidence |
| INV-STAKE-WITHDRAWAL-SAFE | Withdrawal only succeeds when no pending obligations exist |

## Integration Points

### Capability Gate

The `CapabilityStakeGate` is consulted before activating any high-risk capability.
It verifies:
1. Publisher has an active stake record
2. Stake amount meets minimum for the capability's risk tier
3. Publisher has no unresolved slash events

### Audit Trail

All staking operations produce `StakingAuditEntry` records that include:
- Operation type (deposit, slash, appeal, withdraw, expire)
- Timestamp
- Publisher identity
- Stake ID
- Evidence hash (for slash operations)
- Outcome

### Slash Workflow

1. Malicious behaviour detected and evidence collected
2. Evidence validated against policy rules
3. Slash fraction computed from risk tier policy
4. `SlashEvent` created with evidence bundle
5. Stake state transitions to `SLASHED`
6. Appeal window opens (duration per risk tier)
7. If appealed: transition to `UNDER_APPEAL`, resolution required
8. Audit entry emitted at each step

## Schema Version

`staking-v1.0`

## Deterministic Ordering

All internal collections use `BTreeMap` for deterministic iteration order,
ensuring reproducible audit trails and replay-safe slash decisions.
