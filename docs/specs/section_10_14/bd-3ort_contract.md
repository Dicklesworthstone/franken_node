# bd-3ort: Proof-Presence Requirement for Quarantine Promotion

## Overview

Extends quarantine promotion with an `AssuranceMode` that requires
cryptographic proof bundles before artifacts enter the trusted set.

## Module

`crates/franken-node/src/connector/high_assurance_promotion.rs`

## Types

| Type | Purpose |
|------|---------|
| `AssuranceMode` | Standard (proof optional) or HighAssurance (proof required) |
| `ObjectClass` | CriticalMarker, StateObject, TelemetryArtifact, ConfigObject |
| `ProofRequirement` | FullProofChain, IntegrityProof, IntegrityHash, SchemaProof |
| `ProofBundle` | Proof attachments: chain, integrity, hash, schema |
| `PromotionDenialReason` | ProofBundleMissing, ProofBundleInsufficient, UnauthorizedModeDowngrade |
| `PolicyAuthorization` | Authorization for mode changes (policy_ref, authorizer_id, timestamp) |
| `HighAssuranceGate` | Enforces proof-presence per object class and assurance mode |
| `PromotionMatrixEntry` | Object-class x proof-requirement mapping |

## Proof Requirement Matrix

| Object Class | Proof Requirement |
|-------------|-------------------|
| CriticalMarker | FullProofChain (merkle + hash + signature) |
| StateObject | IntegrityProof (hash + signature) |
| TelemetryArtifact | IntegrityHash (hash only) |
| ConfigObject | SchemaProof (schema conformance) |

## Mode Semantics

- **Standard**: All promotions approved regardless of proof presence.
- **HighAssurance**: Promotion requires proof bundle satisfying class requirement.
- **Upgrade** (Standard → HighAssurance): No authorization needed.
- **Downgrade** (HighAssurance → Standard): Requires PolicyAuthorization.

## Invariants

| ID | Rule |
|----|------|
| INV-HA-PROOF-REQUIRED | HighAssurance mode promotion fails without proof bundle |
| INV-HA-FAIL-CLOSED | Missing/insufficient proof → artifact stays quarantined |
| INV-HA-MODE-POLICY | Mode downgrade requires explicit policy authorization |

## Event Codes

| Code | Trigger |
|------|---------|
| QUARANTINE_PROMOTION_APPROVED | Artifact promoted to trusted set |
| QUARANTINE_PROMOTION_DENIED | Promotion denied (proof missing/insufficient) |
| ASSURANCE_MODE_CHANGED | Assurance mode switched |

## Acceptance Criteria

1. HighAssurance mode rejects promotion without required proof bundle.
2. Standard mode allows promotion without proof bundle.
3. Mode downgrade requires PolicyAuthorization.
4. Each object class enforces its specific proof requirement.
5. Promotion matrix artifact is machine-readable.
6. Adversarial tests cover partial/forged bundles and unauthorized downgrade.
