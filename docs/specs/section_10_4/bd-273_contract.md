# bd-273: Extension Certification Levels Tied to Policy Controls

## Bead: bd-273 | Section: 10.4

## Purpose

Defines a tiered certification hierarchy mapping provenance, reputation, and
manifest capabilities into enforceable policy controls. Each level enables or
restricts capabilities, deployment contexts, and operational permissions.

## Invariants

| ID | Statement |
|----|-----------|
| INV-CERT-LEVELS | Five certification levels (uncertified, basic, standard, verified, audited) with non-overlapping criteria. |
| INV-CERT-DETERMINISTIC | Same inputs produce identical certification level assignments. |
| INV-CERT-POLICY-MAP | Every level has explicit capability allow/deny lists. |
| INV-CERT-PROMOTION | Promotion requires explicit evidence and is limited to adjacent levels. |
| INV-CERT-DEMOTION | Demotion triggers automatically on trust data degradation. |
| INV-CERT-REGISTRY | Registry maintains complete change history with signed entries. |
| INV-CERT-DEPLOYMENT | Deployment contexts enforce minimum certification requirements. |
| INV-CERT-AUDIT | Audit trail is append-only with hash-chained integrity. |

## Certification Levels

| Level | Criteria |
|-------|----------|
| Uncertified | No evaluation performed. |
| Basic | Publisher identity verified; manifest capabilities declared. |
| Standard | Provenance chain verified; publisher reputation above provisional threshold. |
| Verified | Reproducible build evidence; test coverage >= 80%. |
| Audited | Independent third-party audit attestation completed. |

## Capability Policy Matrix

| Capability | Uncertified | Basic | Standard | Verified | Audited |
|------------|:-----------:|:-----:|:--------:|:--------:|:-------:|
| FileRead | Y | Y | Y | Y | Y |
| FileWrite | N | Y | Y | Y | Y |
| NetworkAccess | N | N | Y | Y | Y |
| ProcessSpawn | N | N | N | Y | Y |
| CryptoOperations | N | N | Y | Y | Y |
| SystemConfiguration | N | N | N | N | Y |

## Deployment Context Requirements

| Context | Minimum Level |
|---------|--------------|
| Development | Uncertified |
| Staging | Basic |
| Production | Standard |

## Dependencies

- Upstream: bd-ml1 (publisher reputation), bd-1ah (provenance), bd-1gx (manifest schema)
- Downstream: bd-261k (section gate), bd-1xg (plan tracker)
