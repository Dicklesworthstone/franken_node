# DGIS Adversarial Attack Playbook

This playbook is the bd-cclm.1 operator artifact for the DGIS adversarial
validation suite. It binds the concrete regression test
`tests/security/dgis_adversarial_suite.rs` to the adversarial classes from
section 10.20: graph poisoning, edge obfuscation, fake-low-risk pivots, and
delayed activation.

## Campaign Fixtures

| Campaign | Primary tactic | Expected DGIS behavior | Stable class |
| --- | --- | --- | --- |
| `graph_poisoning_non_finite_edge` | Non-finite edge weights and dangling endpoints | Reject before graph admission | `DGIS-ADV-GRAPH-POISONING-REJECTED` |
| `edge_obfuscation_shadow_package` | Namespace-shadow package with sub-threshold edge | Bound spread to the seed package | `DGIS-ADV-EDGE-OBFUSCATION-BOUNDED` |
| `fake_low_risk_pivot_aggregate_exposure` | Two weak independent edges converge on a pivot | Escalate the pivot through aggregate exposure | `DGIS-ADV-FAKE-LOW-RISK-PIVOT-ESCALATED` |
| `delayed_activation_accumulation` | Dormant payload activates only after repeated exposure | Catch through retained exposure memory | `DGIS-ADV-DELAYED-ACTIVATION-CAUGHT` |

## Policy Expectations

- Graph admission is fail-closed: non-finite weights and unknown targets must
  return typed errors before any simulation trace is produced.
- Obfuscated namespace edges below the activation threshold must not silently
  infect payload nodes.
- Low individual edge weights do not imply low risk when multiple independent
  sources converge on the same pivot.
- Delayed activation campaigns require nonzero exposure memory so repeated
  low-amplitude signals still accumulate into a bounded decision.

## Replay Contract

The integration test replays all deterministic fixtures twice and asserts
byte-identical verdicts. The machine-readable result bundle lives at
`artifacts/10.20/dgis_adversarial_results.json` and names each stable failure
class, expected mitigation hint, final infected-node count, termination reason,
and termination step.
