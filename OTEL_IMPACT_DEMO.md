# Your scanner finds what broke. OpenLine finds what was relying on it.

The canonical OpenLine integration demo now lives at:

`examples/otel-impact/`

It connects the existing OpenTelemetry adapter to OpenLine Lite without inventing a new telemetry or messaging stack:

```text
OpenTelemetry → openline-otel → exact signed evidence → openline-impact
```

The deterministic demo freezes 27 prior decisions, invalidates one exact OTel evidence receipt, and produces:

```text
REOPEN          3
RETAIN         22
UNDETERMINED    2
```

Those counts are a demonstration fixture, not a benchmark result. The product claim is narrower: when a receiver froze decision-specific evidence bindings, `openline-impact` can partition standing after an external invalidation without treating every colocated decision as contaminated.

See `examples/otel-impact/README.md` for the pinned dependency, run commands, and trust boundary.
