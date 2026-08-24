# Release verification — v0.6.0

Release base: `openline-lite@5ba5ad4daa25fe5b31b04c4cbec083ef68e51cc2`.

The trust-boundary implementation merged at `5ba5ad4daa25fe5b31b04c4cbec083ef68e51cc2` after the canonical `ci` workflow passed as run `32699140652` and the dedicated `OpenLine Impact` workflow passed as run `32699140655`.

The merged canonical unit suite ran **76 tests** successfully on Python 3.10, 3.11, 3.12, and 3.13. The same merge also passed conformance, package build, clean-wheel smoke, calibration-trial verification, benchmark checks, `openline-check`, and Selective Reverification workflows.

## v0.6.0 release gate

The v0.6.0 release PR must pass the repository's existing CI again after the version and documentation changes. In addition, this release adds checks for:

- package metadata version `0.6.0`;
- `openline_lite.__version__ == "0.6.0"`;
- equality between installed metadata and runtime version;
- runnable `python -m examples.impact`;
- clean-wheel availability of `olp-lite`, `openline-check`, and `openline-impact`.

Do not tag `v0.6.0` unless that release PR is green.

## PSD-001 basis

The productization is bounded by the canonical PSD-001 result preserved in `terryncew/openline-ace`.

Receipt SHA-256:

```text
0ac12393c6de8587e3879c67e51c02a7bd19646fe3be567b58aeb3338988078b
```

The result supports selective decision-specific evidence binding on the frozen external `astral-sh/uv` substrate. It does not support unique graph-algorithm superiority, because the equivalent flat decision-closure index matched exactly.

## Authority boundary

`openline-impact` localizes standing loss. It has `runtime_permission: NONE`.

Receiver policy remains responsible for rollback, retry, isolation, re-review, deployment, or any other consequential response.
