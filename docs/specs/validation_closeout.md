# Validation Closeout Summary

**Report schema:** `franken-node/validation-closeout/report/v1`
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
