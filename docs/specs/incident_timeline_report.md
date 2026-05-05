# Incident Timeline Report

`franken-node/incident-timeline-report/v1` is the JSON contract for
reconstructing an incident from parsed evidence sources. The report normalizes
incident evidence packages and replay bundles into one chronological timeline.

Each normalized event carries:

- `timestamp`
- `monotonic_order`
- `source_artifact`
- `source_digest`
- `actor_node`
- `event_code`
- `severity`
- `verification_status`
- `summary`

The report fails closed. Missing evidence, replay integrity failures,
unverified signatures, clock skew, duplicate or non-monotonic events, and
conflicting node reports are emitted as `gaps` with stable `ITR-*` codes and
operator recovery hints. The Markdown renderer is only a human view over the
same JSON fields; it is not a separate contract.
