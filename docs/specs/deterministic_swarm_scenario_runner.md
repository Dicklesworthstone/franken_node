# Deterministic Swarm Scenario Runner

Schema: `franken-node/deterministic-swarm-scenario/v1`

The deterministic swarm scenario runner exercises product-level fleet, replay,
and incident evidence flows with fixed seeds and timestamps. It is an evidence
runner for release and regression tests, not a mock simulator.

Each scenario declares:

- `scenario_id`
- `seed`
- `base_timestamp`
- `deadline_millis`
- fleet nodes with `node_id`, `zone_id`, `health`, and `quarantine_version`
- optional fault injection
- optional operator incidents with `incident_kind`, `reason_code`,
  `operator_action`, and `evidence_ref`
- expected scenario event codes
- expected evidence artifact paths

The runner must use the real file-backed fleet transport, real incident evidence
package validation, real replay bundle generation, and the incident timeline
report builder. It must not replace those domains with synthetic mocks.

## Registered Scenarios

`all-green-fleet-replay`

- Seeds two healthy fleet nodes.
- Publishes a quarantine action through `FileFleetTransport`.
- Builds an incident evidence package from the persisted fleet action log.
- Generates a replay bundle from that evidence.
- Builds an incident timeline report with verdict `pass`.
- Emits JSONL phase logs and evidence artifacts.

`negative-recovery-fail-closed`

- Seeds one healthy node and one degraded node.
- Publishes the same real fleet action path.
- Generates the incident evidence package and replay bundle.
- Tampers with the replay bundle integrity hash.
- Builds the incident timeline report and requires gap
  `ITR-REPLAY-INTEGRITY`.
- Reports scenario verdict `fail_closed` when the recovery gap is visible and
  actionable.

High-contention operator pack:

- `corrupt-coordination-bead-fallback`
- `blocked-proof-cargo-pressure`
- `quiet-lane-reproof-admission`
- `stale-rch-job-classification`
- `target-dir-lease-choice`
- `source-only-validation-saturation`

These scenarios encode recurring multi-agent contention incidents without live
Cargo or RCH execution. Each fixture still uses the real file-backed fleet
transport, replay bundle builder, and incident timeline builder, then records a
deterministic operator recommendation tied to the generated timeline artifact.
Operators should use the emitted reason code and action line as the incident
decision record when deciding whether to stay source-only, admit a quiet-lane
proof, classify stale RCH progress, or choose an isolated target directory.

## Event Log Contract

Scenario logs are JSONL. Every line contains:

- `timestamp`
- `phase`
- `event_code`
- `success`
- optional `artifact_path`
- optional `assertion_summary`
- `detail`

Stable event codes include:

- `SWARM_SCENARIO_SETUP`
- `SWARM_SCENARIO_FLEET_STATE_SEEDED`
- `SWARM_SCENARIO_FLEET_ACTION_PUBLISHED`
- `SWARM_SCENARIO_REPLAY_BUILT`
- `SWARM_SCENARIO_TIMELINE_BUILT`
- `SWARM_SCENARIO_FAIL_CLOSED_CONFIRMED`
- `SWARM_SCENARIO_OPERATOR_RECOMMENDATION_RECORDED`
- `SWARM_SCENARIO_EVIDENCE_COLLECTED`
- `SWARM_SCENARIO_EXPECTED_EVENTS_CONFIRMED`
- `SWARM_SCENARIO_COMPLETED`
- `SWARM_SCENARIO_ASSERTION_FAILED`

`SWARM_SCENARIO_OPERATOR_RECOMMENDATION_RECORDED` detail fields are stable and
must include `trace_id`, `scenario_id`, `incident_kind`, `reason_code`,
`operator_action`, and `evidence_ref`.

Failed assertions must include `phase`, `event_code`, `expected`, `actual`, and
`artifact_path` fields so operators can identify the failed phase and source
artifact without rerunning the scenario.

## Evidence Artifacts

Each run writes deterministic artifacts under the supplied workspace root:

- `fleet/actions.jsonl`
- `scenario_artifacts/<scenario_id>/incident_evidence.json`
- `scenario_artifacts/<scenario_id>/replay_bundle.json`
- `scenario_artifacts/<scenario_id>/incident_timeline.json`
- `scenario_artifacts/<scenario_id>/scenario_logs.jsonl`

Artifacts are created with `create_new` semantics. A scenario run fails instead
of overwriting existing evidence files.
