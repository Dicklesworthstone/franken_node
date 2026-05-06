# Runbook RB-006: Proof Pipeline Outage

**Category**: proof_pipeline_outage
**Severity**: High
**Estimated Recovery Time**: 30 minutes
**Required Permissions**: operator, pipeline_admin
**Operator Privilege Level**: P2
**Last Reviewed**: 2026-02-21
**Review Cadence**: per_release_cycle

## Detection

### Metrics
- `proof_pipeline_healthy == 0`
- `proof_generation_queue_depth > 1000`
- `proof_verification_latency_p99_seconds > 30`

### Log Patterns
- `PROOF_PIPELINE_OUTAGE_DETECTED`
- `proof_generation_stalled`

## Containment

1. Activate proof pipeline circuit breaker.
2. Queue incoming proof requests (do not drop).
3. Switch to degraded verification mode if available.
4. Alert proof infrastructure team.

## Investigation

1. Identify pipeline stage failure (generation, aggregation, verification, storage).
2. Check proof worker health and resource utilization.
3. Review recent pipeline configuration or dependency changes.
4. Determine whether outage is upstream (input data) or downstream (output storage).
5. Assess backlog depth and estimated drain time.

## Repair

1. Restart failed pipeline workers through the deployment supervisor for the affected environment.
2. Clear any poisoned proof requests from the queue.
3. Scale pipeline workers through the deployment supervisor if backlog exceeds capacity.
4. Fix underlying configuration or dependency issue.

## Verification

1. Confirm pipeline health check returns healthy.
2. Validate proof generation latency returns to baseline.
3. Verify backlog is draining at expected rate.
4. Run end-to-end proof generation test with known input.

## Rollback

1. If repair fails, drain queue to dead-letter storage.
2. Restore pipeline from last known-good configuration.
3. Re-process failed proofs from dead-letter queue.
4. Escalate if pipeline cannot be restored within estimated recovery time.

## Drill Scenario

Simulate proof pipeline outage by pausing proof worker processes in staging.
Verify that detection fires, circuit breaker activates, requests are queued
(not dropped), and pipeline recovery completes after workers are resumed.

## Command References

- `franken-node ops validation-readiness --input <broker-snapshot.json> --receipt <receipt.json> --json`
- `franken-node ops resource-governor --requested-proof-class <proof-class> --source-only-allowed --json`
- Manual: restart or scale proof workers through the deployment supervisor for the active environment.
- Future dedicated proof queue/status and worker restart CLI/API surface: bd-rm6ex.

## Cross-References

- Proof pipeline subsystem
- Verification infrastructure
- Queue management and circuit breaker patterns
