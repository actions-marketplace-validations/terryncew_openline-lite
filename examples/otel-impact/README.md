# OpenTelemetry → OpenLine Impact

**Your observability stack tells you what happened. OpenLine tells you what that new fact invalidates.**

This is the canonical bridge demo between the existing `openline-otel` distribution rail and `openline-lite`'s `openline-impact` product surface.

```text
ordinary OpenTelemetry spans
          ↓
openline-otel
signed provisional trace receipts
          ↓
receiver freezes exact evidence bindings at decision time
          ↓
one evidence hash is invalidated externally
          ↓
openline-impact
          ↓
REOPEN 3 · RETAIN 22 · UNDETERMINED 2
```

The important boundary is selective standing, not a new alert detector. `openline-otel` captures and signs what it observed. The invalidation in this demo is supplied externally. `openline-impact` then answers which prior decisions were actually bound to those exact evidence bytes.

## Run

From the root of `openline-lite`:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m pip install -r examples/otel-impact/requirements.txt
python examples/otel-impact/demo.py
python examples/otel-impact/verify_demo.py .openline-otel-impact
```

Expected terminal shape:

```text
OPENLINE: OTel -> IMPACT

Evidence revoked: dependency-observation
sha256:<exact receipt bytes>

Affected standing:
REOPEN         3
RETAIN        22
UNDETERMINED   2

Only decisions bound to the revoked evidence reopen.
No remediation executed. Runtime permission: NONE
```

The demo deliberately co-locates all three OTel observations in every source receipt. Receiver policy binds each decision to only one required observation. Revoking the dependency observation must therefore reopen the three decisions that actually required it without reopening the 22 complete decisions bound to other observations.

Two additional decisions declare their binding incomplete. They become `UNDETERMINED`, never silently `RETAIN`, demonstrating the same conservative boundary as OLP Standing Profile.

## Pinned integration

`openline-otel` is pinned to commit:

```text
19bcef659e59704b71ed6f1ac910253a60f369ab
```

The demo uses real `opentelemetry-sdk` spans and `OpenLineReceiptProcessor`; it separately verifies each emitted OpenLine OTel signature before those exact bytes are used as evidence artifacts.

## Claim boundary

This is an integration demonstration, not a new empirical benchmark. The 3/22/2 partition is deliberately constructed and must not be presented as natural-world prevalence or performance.

The OTel receipts remain `attestation: self` and `capture_status: provisional`; a valid signature is not proof that telemetry is complete or true. The demo does not discover the upstream break, infer omitted dependencies, repair state, roll anything back, or authorize execution. `openline-impact` only localizes the standing consequence of an externally supplied invalidation.
