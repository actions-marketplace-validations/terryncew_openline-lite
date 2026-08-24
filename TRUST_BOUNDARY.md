# Decision Trust Boundary

OpenLine Lite can flatten already signed `VERIFIED / COMMIT` decisions into a
reverse evidence index.

The operational question is:

> Evidence X lost standing. Which standing decisions actually depended on X?

The primitive is deliberately smaller than a graph engine:

```text
signed COMMIT receipt + exact signed source receipt
                    ↓
     required evidence SHA-256 bindings
                    ↓
        EvidenceHash → DecisionIDs
                    ↓
             invalidation
          ↙      ↓       ↘
      REOPEN   RETAIN   UNDETERMINED
```

`REOPEN` means the revoked evidence hash appears in the decision's frozen
binding.

`RETAIN` is permitted only when the receiver declared the binding `COMPLETE`
and none of the invalidated hashes appears in it.

`UNDETERMINED` means the binding was explicitly marked `INCOMPLETE` and no
known path proves the decision affected. Missingness never silently becomes
independence.

## Why this is separate from selective reverification

`openline_lite.continuity` retains the richer dependency graph and can return
the path by which a changed root reaches a claim.

`openline-impact` is the flattened critical-path view. It is intended for the
common operational case where the receiver already froze the dependency
closure at decision time and later needs a bounded reverse lookup.

The two representations should agree when they encode the same complete
bindings. A flat index is not claimed to be less correct or less powerful for
that lookup.

## Input

`openline-impact` consumes an `openline.impact-pack.v1` file:

```json
{
  "schema": "openline.impact-pack.v1",
  "gate_trust": "gate-trust.json",
  "producer_trust": "producer-trust.json",
  "decisions": [
    {
      "decision_receipt": "decision-a.json",
      "source_receipt": "source-a.json",
      "binding_completeness": "COMPLETE",
      "label": "deploy api"
    }
  ],
  "invalidated_evidence_sha256": [
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  ]
}
```

The tool verifies the receiver-signed decision receipt against pinned gate
keys, requires `VERIFIED / COMMIT`, verifies the producer source receipt
against pinned producer keys, checks the decision's exact source-byte hash,
and binds only evidence IDs required by the frozen receiver policy.

A non-required artifact present in the same source receipt does not expand the
decision's invalidation boundary.

## Output and authority

The output contains a deterministic hash-bound index and result partition.
It does not issue COMMIT, DENY, rollback, deployment, audit, or agent-control
authority.

Receiver policy decides what to do with `REOPEN` and `UNDETERMINED`.

`policy_authority: receiver_owned`  
`runtime_permission: NONE`
