# Selective Reverification

OpenLine Check can optionally determine which previously standing evidence may
still be inherited after state changes.

This is deliberately not a similarity score and not another decision engine.

The receiver supplies a small dependency graph:

```json
{
  "schema": "openline.continuity.v1",
  "claims": ["tests-standing", "review-standing", "merge-ready"],
  "edges": [
    ["artifact:patch", "tests-standing"],
    ["tests-standing", "merge-ready"],
    ["artifact:review", "review-standing"]
  ],
  "changed": ["artifact:patch"],
  "required_claims": ["tests-standing", "review-standing"],
  "evidence_bindings": {
    "tests-standing": ["tests"],
    "review-standing": ["review"]
  }
}
```

The algorithm follows descendants from the changed roots. Claims outside those
paths retain standing. If a reopened claim is receiver-declared as required for
the action, its bound evidence is withheld from the existing Receipt Gate until
that evidence is reverified.

For the example above:

```text
Standing retained:
- review-standing

Reverification required:
- tests-standing [required]: artifact:patch -> tests-standing
- merge-ready: artifact:patch -> tests-standing -> merge-ready

Evidence withheld pending reverification:
- tests

Disposition: QUARANTINE
```

The Gate still owns the disposition. Selective Reverification cannot emit
COMMIT, QUARANTINE, or DENY on its own.

## Boundary

Selective Reverification assumes the receiver's dependency declaration is
correct enough for the decision. It does not discover dependencies, infer
causality, score truth, or establish safety.

A missing dependency can cause false retention. Receivers should therefore
treat dependency-map construction as evidence-bearing configuration and review
it accordingly.

`policy_authority: receiver_owned`

`runtime_permission: NONE`
