# bd-1vm: Fast Quarantine/Recall Workflow for Compromised Artifacts

## Bead: bd-1vm | Section: 10.4

## Purpose

Implements the "immune response" for the extension ecosystem: quarantine
isolates threats while investigation proceeds, recall removes compromised
artifacts from all nodes. The workflow integrates with revocation propagation
for signal delivery and trust cards for status visibility.

## Invariants

| ID | Statement |
|----|-----------|
| INV-QUAR-MODES | Two quarantine modes: soft (new installs blocked, existing warned) and hard (existing disabled with grace period). |
| INV-QUAR-FAST-PATH | Critical severity quarantines bypass normal flow and trigger immediate enforcement. |
| INV-QUAR-FAIL-CLOSED | If quarantine status cannot be determined, the extension is treated as quarantined. |
| INV-QUAR-DURABLE | Quarantine state survives node restarts and network partitions; catch-up on reconnect. |
| INV-QUAR-LIFECYCLE | Full state machine: Initiated -> Propagated -> Enforced -> Draining -> Isolated -> Lifted or RecallTriggered -> RecallCompleted. |
| INV-QUAR-CLEARANCE | Quarantine lift requires explicit signed clearance with non-empty justification (no automatic timeout). |
| INV-QUAR-RECALL-VERIFY | Recall requires prior quarantine; each node confirms artifact removal with receipt. |
| INV-QUAR-AUDIT | Audit trail is append-only with SHA-256 hash-chained integrity. |

## Quarantine Triggers

| Trigger | Source |
|---------|--------|
| VulnerabilityDisclosure | External CVE or security advisory. |
| MalwareDetection | Automated scanning detected malware. |
| SupplyChainAttack | Evidence of supply-chain compromise. |
| BehavioralAnomaly | Runtime behavioral anomaly detection. |
| OperatorInitiated | Manual operator investigation. |
| RevocationEvent | Revocation from supply-chain module. |
| PolicyTrigger | Automated incident detection policy. |

## State Machine

```
Initiated -> Propagated -> Enforced -> Draining -> Isolated
                                                      |
                                             +--------+--------+
                                             |                 |
                                          Lifted      RecallTriggered
                                                           |
                                                    RecallCompleted
```

Critical severity: Initiated -> Enforced (fast-path, skips Propagated).

## Event Codes

| Code | When Emitted |
|------|--------------|
| QUARANTINE_INITIATED | Order issued, propagation started. |
| QUARANTINE_PROPAGATED | Signal delivered to a node. |
| QUARANTINE_ENFORCED | Extension suspended on local node. |
| QUARANTINE_DRAIN_STARTED | Active sessions being drained. |
| QUARANTINE_DRAIN_COMPLETED | All sessions drained, extension isolated. |
| QUARANTINE_LIFTED | Quarantine cleared with signed clearance. |
| RECALL_TRIGGERED | Recall initiated after confirmed compromise. |
| RECALL_ARTIFACT_REMOVED | Single node confirmed artifact removal. |
| RECALL_RECEIPT_EMITTED | Recall receipt logged. |
| RECALL_COMPLETED | All nodes confirmed removal. |

## Impact Report

Each quarantine generates a structured impact report containing:
- Number of installations affected
- Data at risk description
- Dependent extensions list
- Active sessions count
- Recommended operator actions

## Dependencies

- Upstream: bd-12q (revocation propagation), bd-1gx (manifest schema)
- Downstream: bd-261k (section gate), bd-yqz (fleet quarantine UX), bd-1xg (plan tracker)
