# Capability Prompts (UX Spec)

This document defines the user-facing experience for extension capability prompts:
what users see, what they can decide, how decisions are persisted, and how the
flow works in both the interactive TUI and headless RPC mode.

This spec is intended to be consistent with:
- `EXTENSIONS.md` (capability taxonomy + policy modes + hostcall ABI)
- `src/permissions.rs` (current persistence shape; will need extension for scopes)
- `docs/rpc.md` (JSONL RPC request/response/event framing)

## Goals

- Provide informed consent without overwhelming the user.
- Avoid prompt spam: batch requests when safe and meaningful.
- Make decisions auditable (structured logs, stable correlation IDs).
- Ensure deterministic behavior in headless mode (timeouts, defaults).

## Non-Goals

- Implementing the capability policy engine itself (this is UX + interaction spec).
- Allowing extensions to draw arbitrary UI (core owns UI).

## Terms

- **Capability**: a policy key such as `read`, `write`, `exec`, `http`, `session`, `ui`, `tool`.
  The key MUST match core-derived capability for a hostcall (see `EXTENSIONS.md` §3.2).
- **Scope**: the concrete resource being accessed (path/host/command/etc).
- **Hostcall**: an extension-to-core privileged request (`host_call` / `host_result`).
- **Prompt**: a user-visible question asking for a capability decision.
- **Decision**: allow/deny outcome, with persistence semantics.

## Hostcall Types Covered

This spec covers capability prompts for these connector methods:

| Method | Typical capability | Scope shown to user |
|---|---|---|
| `tool` | derived from tool name (`read`/`write`/`exec`/`tool`) | tool name + key params (path/pattern/etc) |
| `exec` | `exec` | command + args (redacted where needed) |
| `http` | `http` | scheme + host + method + path (query redacted by default) |
| `session` | `session` | operation name (e.g. `get_messages`, `fork`, `compact`) |
| `ui` | `ui` | operation name (e.g. `confirm`, `input`, `select`, `editor`) |

## Risk Classification Rubric

Risk is shown as a simple, consistent indicator. Classification is deterministic.

### Base Risk by Capability

| Capability | Risk | Rationale |
|---|---|---|
| `exec` | High | arbitrary process execution |
| `write` | High | filesystem mutation / data loss |
| `http` | Medium | data exfil + network side effects |
| `read` | Medium | secrets exposure (depends on scope) |
| `tool` | Medium | unknown/custom tool (forces prompt/deny in strict/prompt modes) |
| `session` | Low | Pi-internal metadata only |
| `ui` | Low | user interaction only (but may be denied in headless mode) |

### Scope Escalators (Optional, Deterministic)

Scope can only increase risk, never decrease it.

- `read` escalates to High if the path matches common secret patterns:
  `.env`, `**/*secret*`, `**/*token*`, `**/.ssh/**`, `**/*credentials*`.
- `http` escalates to High if host is not in the extension’s declared/inferred host scope.
- `exec` remains High always.

If scope is dynamic/unknown (non-literal), display scope as `"<dynamic>"` and
escalate to the higher risk level for that capability.

## Prompt Content Specification

Each prompt MUST include:

- **Extension identity**:
  - display name
  - `extension_id`
  - version (if known)
  - source (npm/GitHub/local path) if known
- **Capability requested**:
  - capability key (e.g. `http`)
  - human-readable description (e.g. "Network access")
- **Scope summary** (redacted by default):
  - path / host / command / operation
  - show a short preview plus a "details" toggle
- **Risk indicator**:
  - `LOW`, `MEDIUM`, `HIGH` label
  - short, concrete justification ("exec can run arbitrary commands")
- **Batch summary** (if batched):
  - number of pending requests
  - list of up to 3 representative scopes, then `+N more`
- **Decision options** (see below)

### Redaction Rules (Prompt UI)

The prompt UI must never display likely secrets by default.

- For `exec`: do not show full environment, and redact tokens in arguments.
- For `http`: show host + path; hide query string by default unless user expands details.
- For `read`/`write`: show normalized relative paths; do not inline file contents.

## Decision Options

The prompt presents a small, fixed set of decisions:

1. **Allow Once**
   - Applies only to this single hostcall (one `call_id`).
2. **Allow For Session**
   - Applies to the current Pi session only (cleared when session ends).
3. **Allow Always**
   - Persisted decision (see Persistence Model).
4. **Deny**
   - Deny this single hostcall.
5. **Deny Always**
   - Persisted deny decision (see Persistence Model).

Notes:
- In `extensions.policy.mode=strict`, "prompt" UI is normally not shown; requests
  without an allow rule are denied. The UI may still be used if the user invokes
  an explicit "grant" flow (future).
- In `extensions.policy.mode=permissive`, the prompt should be suppressed by
  default and decisions are logged; an "always prompt" debug override may exist.

## Batching / Grouping Rules

Batching reduces spam while preserving informed consent.

### Prompt Key

Requests are batched by:

- `extension_id`
- `capability`
- `risk_level`
- `scope_group` (method-specific normalization; examples below)

Never batch across:
- different capabilities
- different risk levels
- different extensions

### Scope Grouping (Deterministic)

- `read`/`write` (tool or fs): group by top-level directory in the normalized path
  (e.g. `src/**`, `tests/**`). If path is `"<dynamic>"`, it is its own group.
- `http`: group by host (e.g. `api.github.com`). If host is unknown/dynamic, its own group.
- `exec`: do not group across different command binaries (first argv token).
- `session`/`ui`: group by operation name.

### Batching Window

- Collect requests for a short window: `250ms` from the first queued request,
  then prompt once with the batch.
- While a prompt is displayed, additional requests matching the same Prompt Key
  are appended to the batch (counts update live), but the UI should avoid
  scrolling; show only count + a short representative list.

### Batching Algorithm (Pseudocode)

```text
on_hostcall_request(req):
  cap = derive_capability(req.method, req.params)
  decision = lookup_cached_or_persisted(ext_id, cap, scope)
  if decision == ALLOW: dispatch
  if decision == DENY: return denied

  if policy.mode == strict: return denied
  if policy.mode == permissive: dispatch (log policy.decision=allow_permissive)

  // prompt mode:
  key = PromptKey(ext_id, cap, risk(cap, scope), scope_group(scope))
  enqueue pending[key].push(req)
  if no prompt scheduled for key:
    schedule after 250ms: show_prompt(key)

show_prompt(key):
  prompt_id = new_id()
  display prompt for pending[key]
  wait for decision (TUI or RPC), timeout 30s -> deny
  apply decision to pending[key] requests
  clear pending[key]
```

## Persistence Model

### Target Key

Persisted decisions are keyed by:

`(extension_id, capability, scope_pattern, version_range?) -> decision`

Where:
- `scope_pattern` is optional for capabilities without scope (exec/session/ui).
- `version_range` is optional semver constraint (re-prompt when extension changes).

### Scope Pattern Semantics

- Paths: glob-like patterns relative to project root/cwd (same semantics as
  `EXTENSIONS.md` capability manifests).
- Hosts: exact host or suffix match (`api.github.com`, `*.github.com`).
- Exec: optional command prefix glob (`git *`, `rg *`).

### Storage

Current implementation (`src/permissions.rs`) persists `(extension_id, capability)`.
To satisfy this spec, it will need to be extended to include `scope_pattern` and
to treat scope-less entries as a wildcard for that capability.

## Interactive TUI Wireframe

ASCII mockup (modal overlay):

```text
┌──────────────────────────────────────────────────────────────────────┐
│ Extension Permission Request                                          │
├──────────────────────────────────────────────────────────────────────┤
│ Extension:  Auto Commit on Exit  (ext.auto_commit)  v1.2.0           │
│ Source:     npm:@user/pi-auto-commit                                 │
│                                                                      │
│ Requested:  EXEC  (High Risk)                                        │
│ Reason:     exec can run arbitrary commands on your machine          │
│                                                                      │
│ Scope:      git commit -am "<redacted>"                              │
│ Batch:      3 pending exec requests (showing 1/3)                    │
│            - git status                                              │
│            - git commit ...                                          │
│            - +1 more                                                 │
│                                                                      │
│ [A] Allow once   [S] Allow for session   [Y] Allow always            │
│ [D] Deny         [N] Deny always         [?] Details / help          │
└──────────────────────────────────────────────────────────────────────┘
```

Interaction rules:
- Default focus is on the least-privileged positive option (`Allow once`).
- `?` expands a details panel (full normalized params, redaction notes, links).
- A visible countdown is optional; timeout is enforced even if not shown.

## Headless / RPC Mode

In RPC mode, prompts are delivered as server-sent events and must be answered by
an explicit client command.

### Event: `capability_prompt`

```json
{
  "type": "capability_prompt",
  "data": {
    "promptId": "perm-123",
    "callIds": ["host-7", "host-8"],
    "extension": {
      "id": "ext.auto_commit",
      "name": "Auto Commit on Exit",
      "version": "1.2.0",
      "source": { "type": "npm", "ref": "@user/pi-auto-commit" }
    },
    "capability": "exec",
    "method": "exec",
    "risk": "high",
    "scopes": [
      { "kind": "command", "summary": "git status" },
      { "kind": "command", "summary": "git commit ..." }
    ],
    "options": ["allow_once", "allow_session", "allow_always", "deny_once", "deny_always"],
    "timeoutMs": 30000
  }
}
```

### Command: `capability_decision`

Client responds:

```json
{
  "id": "req-55",
  "type": "capability_decision",
  "promptId": "perm-123",
  "decision": "allow_once"
}
```

Server replies with standard response envelope (`docs/rpc.md`):

```json
{
  "id": "req-55",
  "type": "response",
  "command": "capability_decision",
  "success": true,
  "data": null,
  "error": null
}
```

### Timeout Behavior

- If no decision is received within `timeoutMs` (default 30s), Pi MUST:
  - deny all pending `callIds`,
  - emit `policy.decision` logs with `decision="deny_timeout"`.

## Logging Requirements

Every prompt resolution MUST emit a structured log event (`pi.ext.log.v1`):

- `event`: `policy.decision`
- `data` fields:
  - `prompt_id`
  - `call_ids[]`
  - `extension_id`
  - `capability`
  - `decision` (`allow_once`, `allow_always`, `deny_always`, etc.)
  - `policy_mode` (`strict`, `prompt`, `permissive`)
  - `risk`
  - `scope_hashes[]` (sha256 of canonical scope summaries; never raw secrets)

## Open Questions (Explicit)

- Exact scope-pattern language for exec commands (glob vs prefix vs regex).
- Whether `read` should default to Low when scope is strictly inside `src/**` (currently: Medium).
- Whether `ui` capability should auto-allow in interactive mode (currently: promptable like others).

