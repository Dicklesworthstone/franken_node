# Validation Closeout Summary

**Report schema:** `franken-node/validation-closeout/report/v1`
**Completion-audit schema:** `franken-node/completion-audit-ledger/v1`
**Command:** `franken-node ops validation-closeout`

`ops validation-closeout` renders one validation broker receipt into deterministic
closeout text for Beads and Agent Mail. It does not close Beads and does not
write Agent Mail; agents still perform those coordination steps explicitly.

## Inputs

```bash
franken-node ops validation-closeout \
  --bead-id bd-example \
  --receipt artifacts/validation_broker/bd-example/receipt.json \
  --trace-id closeout-bd-example \
  --json
```

Optional `--stdout-excerpt` and `--stderr-excerpt` paths include bounded output
snippets. `--max-output-bytes` defaults to 4096 bytes per stream and preserves
valid UTF-8 before appending a truncation marker.

## Status Values

| Status | Meaning |
|---|---|
| `ready` | Receipt is fresh, valid, and exits successfully. |
| `source_only` | Receipt is valid but records an explicit source-only fallback. |
| `blocked` | Receipt is valid but represents failed, timed out, or cancelled proof. |
| `stale` | Receipt schema is parseable but freshness validation failed. |
| `invalid` | Receipt is malformed, mismatched, or otherwise not closeout evidence. |

## Output Contract

JSON output includes:

- `close_reason` suitable for `br close --reason`
- `agent_mail_markdown` suitable for a completion reply
- command, exit, timeout, retry, RCH worker, artifact paths, receipt freshness,
  source-only caveats, and warnings
- optional bounded stdout/stderr excerpts

Human output prints the same `agent_mail_markdown` body. Agents must still
inspect the status before closing Beads: only `ready` is a green proof.

## Prompt-To-Artifact Completion Audit

Closeout reports may include a `completion_audit` object using schema
`franken-node/completion-audit-ledger/v1`. The audit maps the original
objective into concrete requirements and evidence so a green receipt cannot be
confused with proof that every requested deliverable was actually covered.

Each requirement records:

- `requirement_id` and `requirement_text`
- normalized `status`, `reason_code`, and `required_action`
- evidence references for files, commands, tests, gates, artifacts, Beads,
  Agent Mail threads, manifests, verifiers, and other proof surfaces
- `coverage` as either `direct` or `proxy`
- evidence `status` as `fresh`, `stale`, `missing`, or `blocked`

Ledger status is deterministic and sorted by requirement/evidence ID. A ledger
is green only when every requirement has fresh direct evidence:

| Audit status | Reason code | Required action |
|---|---|---|
| `proven` | `VC_AUDIT_PROVEN` | `close_with_direct_evidence` |
| `proxy_only` | `VC_AUDIT_PROXY_ONLY` | `replace_proxy_with_direct_evidence` |
| `missing_evidence` | `VC_AUDIT_MISSING_EVIDENCE` | `collect_missing_evidence` |
| `stale` | `VC_AUDIT_STALE_EVIDENCE` | `refresh_stale_evidence` |
| `blocked` | `VC_AUDIT_BLOCKED_PROOF` | `record_blocker_and_retry` |

When `completion_audit.status` is not `proven`, the closeout report keeps the
validation receipt status visible but adds a warning, close-reason fields, Agent
Mail summary lines, and structured-log fields showing the audit blocker. Agents
must treat `status=ready` plus `completion_audit.status!=proven` as incomplete
closeout evidence.

Completion-audit path evidence follows the resource-governor safety posture:
paths are bounded, NUL bytes and parent traversal are rejected, and protected
workspace state such as `.beads`, `.agent-mail`, and Agent Mail archive paths is
not accepted as file/artifact evidence. Bead IDs and Agent Mail thread IDs are
recorded in their own fields instead of smuggling those protected stores through
path evidence.
