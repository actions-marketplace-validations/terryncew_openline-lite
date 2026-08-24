# OpenLine Lite v0.6.0 release kit

## Release title

`OpenLine Lite v0.6.0 — Know the boundary of lost trust`

## Release body

OpenLine Lite v0.6.0 adds a second receiver-owned question beside “may this action proceed?”:

> Evidence X lost standing. Which previously accepted decisions actually depended on it?

The new `openline-impact` command verifies signed standing decisions and exact signed source receipts, flattens receiver-required evidence bindings into `EvidenceHash → DecisionIDs`, and partitions the result into:

- `REOPEN` — the invalidated evidence is explicitly bound to the decision;
- `RETAIN` — no invalidated evidence is bound and the receiver declared the binding complete;
- `UNDETERMINED` — the binding is known to be incomplete, so absence cannot be treated as independence.

It does not discover the original break, infer missing dependencies, authorize execution, or perform rollback. Receiver policy remains the authority for what happens after the partition.

Why the flat index? PSD-001 prospectively froze 30 decisions on a pinned external `astral-sh/uv` workspace before blind dependency invalidations were chosen. Across 24 complete trials, decision-specific binding preserved 1.000 recall and 1.000 precision with zero false reopenings; the artifact-level join preserved recall but had about 0.415 precision. A flat decision-specific closure index matched graph traversal exactly. The earned claim is therefore decision-specific binding, not graph-algorithm superiority.

Canonical PSD-001 receipt SHA-256:

`0ac12393c6de8587e3879c67e51c02a7bd19646fe3be567b58aeb3338988078b`

v0.6.0 also fixes a stale version seam: package metadata and `openline_lite.__version__` are both `0.6.0`, with a regression test that prevents future drift.

Run it:

```bash
pip install .
openline-impact --help
python -m examples.impact
openline-check --help
olp-lite demo
```

Status remains alpha. The result does not establish early warning, prediction, causal discovery, autonomous repair, complete dependency capture, hardware-backed key custody, or production safety.

## Tag

```text
v0.6.0
```

## Suggested launch post

> Something upstream breaks. Most systems know how to panic. The harder question is what actually lost standing.
>
> OpenLine Lite v0.6.0 adds `openline-impact`: invalidate one evidence receipt and get a bounded `REOPEN / RETAIN / UNDETERMINED` partition over prior signed decisions. The point is smaller blast radius, not smarter guessing.
