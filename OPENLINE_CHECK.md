# OpenLine Check

`openline-check` is the opinionated front door to OpenLine Lite.

```bash
openline-check .openline/check.json
```

It does not create a new trust model. It loads a signed source receipt, receiver-pinned
producer trust, a receiver policy, and the exact evidence bytes; then it runs the existing
OpenLine Lite Evidence Gateway and Receipt Gate.

The visible output is deliberately small:

```text
OPENLINE CHECK

Action: merge PR #481 -> 8c91...
Evidence standing: UNDECIDABLE
Disposition: QUARANTINE

Why:
- freshness:receipt_expired

What would clear it:
- Refresh the source receipt and bind it to the current action.
```

The complete signed decision remains in `.openline-check/decision.receipt.json`.

## Check pack

Paths are relative to the check pack and may not escape its directory.

```json
{
  "schema": "openline.check.v1",
  "label": "Merge PR #481",
  "source": "source.receipt.json",
  "producer_trust": "producer-trust.json",
  "policy": "receiver-policy.json",
  "evidence": {
    "tests": "evidence/tests.json",
    "review": "evidence/review.json"
  }
}
```

Missing evidence files are not CLI errors. They reach Receipt Gate as unavailable evidence and
therefore fail closed under receiver policy. Malformed control files and path escapes remain hard
errors.

The first profile accepts native `olp.source.v1` receipts only. Foreign receipt adapters remain
available through the lower-level `olp-lite` surface; `openline-check` does not silently turn
arbitrary trace JSON into semantic claims.

## Gate key

For the shortest local run, omit the gate key. OpenLine Check creates an ephemeral Ed25519 key and
marks the proof card accordingly. That decision is integrity-checkable but has no externally pinned
gate authority.

For a durable receiver identity:

```bash
olp-lite keygen --out .openline/gate.key
openline-check .openline/check.json \
  --gate-key .openline/gate.key \
  --gate-id my-ci-gate
```

CI may provide the raw hex key through `OPENLINE_GATE_PRIVATE_KEY`.

## GitHub Action

The repository root is also a composite GitHub Action:

```yaml
- uses: actions/checkout@v4
- uses: terryncew/openline-lite@main
  with:
    check-pack: .openline/check.json
    gate-id: repo-ci
    gate-key: ${{ secrets.OPENLINE_GATE_PRIVATE_KEY }}
```

Any disposition other than `COMMIT` fails the step. The proof card is appended to the GitHub Step
Summary, and `.openline-check/` contains the machine-readable result and signed decision.

## Boundary

`COMMIT` means the receiver-owned policy passed against the presented, verified evidence. It does
not establish complete capture, producer honesty, semantic truth outside the bounded claim rules,
or authority for another receiver. An ephemeral gate key does not create portable trust merely
because its signature verifies.
