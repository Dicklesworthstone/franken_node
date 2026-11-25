# Guarded fleet policy rollout

`fleet policy rollout` performs a complete maintenance-owned policy change with one command. It creates a persistent admission hold, waits for fresh terminal held observations, publishes the restrictive policy atomically under that hold, waits for the exact post-policy checkpoints, releases only its own hold through a guarded transaction, and waits for that release to be acknowledged.

## Run a rollout

Keep the intended executable policy in a file, for example `policy.json`:

```json
{
  "minimum_profile": "strict",
  "max_instructions": 1000000,
  "block_private_network": true
}
```

Configure the same fleet store or HTTP coordinator used by the fleet agents, and provision the fleet receipt signing key using the existing `security.decision_receipt_signing_key_path` setting or `FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH`. The command refuses a missing signer before creating a hold. It never generates a signing key implicitly.

```sh
franken-node fleet policy rollout \
  --id hardening-east-2026-11 \
  --zone east \
  --revision 7 \
  --file policy.json \
  --timeout-seconds 300 \
  --poll-interval-ms 250 \
  --json
```

Use `--zone all` for fleet-wide policy. Revisions are positive and monotonic within the exact policy scope, and new policies must preserve existing restrictions. Agents must keep polling while the command runs. A node's fresh heartbeat alone cannot acknowledge policy application: its native drain and application checkpoint must match the exact retained action snapshot.

The default timeout is 300 seconds and polling interval is 250 milliseconds. The timeout is one shared budget across connection initialization, HTTP requests, database waits, and all rollout phases. The final coordinator release also carries a wall-clock expiration checked within the admitting transaction. Poll intervals must be 10–5000 milliseconds, and timeout must be 1–86400 seconds. Choose a budget longer than your agents' normal observation interval.

## Ownership, participants, and retries

The required `--id` binds a deterministic hold, policy action, and resume action. Its hold reason binds the policy digest, which covers the revision and executable policy. Reusing the same ID with different policy contents, revision, or zone fails before further publication. For a new intended change, choose a new ID.

Participants include every target node already retained in the durable store and every node observed during the operation. Nodes joining during the rollout must acknowledge the current snapshot. A missing or stale participant does not disappear from the requirement. The coordinator's guarded publication receipt retains the admitted population for recovery, and the durable inventory does not evict missing nodes. HTTP rollout requires enrolled node credentials; operator-only heartbeat claims cannot substitute for enrolled observations.

The command releases only the hold it created. Independent operator holds remain in force. Consequently, a completed rollout can report `evidence.admission_resumed: false` when another hold still fences admission. Quarantines and other independent restrictions also remain authoritative.

On interruption, timeout, or lost response, repeat the **same command with the same ID, zone, revision, and policy file**. You may give that retry a new time budget. The operation recovers retained timestamps and original durable receipts instead of creating duplicate actions.

A timeout before guarded release leaves the operation's hold in force. If the release committed but its response was lost or arrived too late, the command cannot infer that admission stayed fenced. Retry recovers the original release receipt and observes the current acknowledgement state. There is no automatic compensating release on timeout or refusal, and no automatic rollback of a committed policy.

A newer policy in the same scope prevents an unfinished older rollout from automatically releasing its hold, even if nodes have acknowledged the newer snapshot. Inspect the retained state and resolve that operation deliberately with the existing maintenance commands.

## Interpret the result

With `--json`, the command emits one `franken-node/fleet-policy-rollout-cli/v1` report and exits nonzero when incomplete. The signed `receipt.payload` includes transport identity and the nested `rollout`:

| Field | Meaning |
| --- | --- |
| `rollout_id`, `hold_action_id`, `policy_action_id`, `resume_action_id` | Stable recovery identities. |
| `phase` | Last reached stage: holding, publishing, applying, resuming, or complete. |
| `completed` | The operation's own release has been acknowledged by the retained population. |
| `timed_out` and `error` | Why the operation did not establish completion. |
| `guarded_publication` | Original evidence accepted atomically with policy publication. |
| `guarded_resume` | Original evidence accepted atomically with this owner's release, when confirmed. |
| `evidence` | Most recent exact-snapshot observation, including remaining active holds. |

A recovered receipt keeps its original acceptance time and evidence, changing only its explicit retry flag. Historical acceptance does not assert current node readiness; the command obtains fresh observations before reporting current completion.

The policy enforcement scope is **new run admission**. These ordinary maintenance receipts report `fleet_quiescence_certified: false`. They do not replace the separate enrolled-supervisor epoch-barrier certificate workflow or claim process-tree quiescence.

## Safety boundaries

The resume transaction verifies the original guarded policy publication, its owner and participant set, the policy still effective in that exact scope, the exact full action-log checkpoint, current fresh terminal held observations, and the release deadline. It writes the resume action and its recovery receipt together. Another publication or node update between a client poll and coordinator admission cannot turn an obsolete readiness observation into an authorized release.

Guarded policy publication and resume recheck observation validity immediately before the durable commit, after signature verification, serialization, and staged database writes. The earliest heartbeat or signed supervisor expiry across the required population controls this check; a newer heartbeat cannot renew an older signed drain. Evidence that expires during admission, or a coordinator clock that moves backward, rolls back the staged action and receipt. Obtain fresh acknowledgements and retry the same intended operation. Already committed retries continue to return the original historical receipt.
