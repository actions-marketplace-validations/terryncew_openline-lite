# Changelog

## 0.6.0 — 2026-08-23

- Added `openline-impact`, a flat reverse evidence index for locating which standing decisions lose standing after an evidence invalidation.
- Added strict `REOPEN`, `RETAIN`, and `UNDETERMINED` partitioning.
- Allowed `RETAIN` only for receiver-declared complete bindings; incomplete bindings fail closed to `UNDETERMINED` when no known match exists.
- Bound Impact decisions to verified receiver-signed `VERIFIED / COMMIT` receipts, exact source-receipt bytes, pinned producer trust, and receiver-required evidence commitments.
- Prevented colocated but non-required evidence from expanding the invalidation boundary.
- Added deterministic hash-bound Impact index and result objects.
- Added 18 adversarial Impact tests and a Python 3.10–3.13 dedicated workflow.
- Added a runnable three-decision Impact example.
- Added a permanent test requiring package metadata and `openline_lite.__version__` to agree.
- Updated the public product framing around the boundary of lost trust.

Research boundary: PSD-001 supports decision-specific evidence binding versus coarse artifact/repository joining on one frozen external `astral-sh/uv` substrate. An equivalent flat decision-specific index matched graph traversal exactly, so v0.6.0 does not claim unique graph-algorithm superiority.

## 0.5.0 — 2026-08-21

- Added optional Selective Reverification to `openline-check`.
- Added receiver-declared dependency graphs that propagate reopening from changed roots through affected claim descendants.
- Added explicit required-claim-to-evidence bindings so reopened required claims withhold only their bound evidence from Receipt Gate.
- Added proof-card sections for standing retained, reverification required, dependency paths, and evidence withheld pending reverification.
- Preserved backward compatibility: check packs without a `continuity` object use the existing v0.4.0 path unchanged.
- Added bounded graph limits, duplicate/unknown-binding validation, cycle-safe traversal, and fail-closed malformed-control handling.
- Added adversarial integration coverage for patch changes, review changes, unrelated changes, cycles, unknown evidence bindings, and backward compatibility.
- Retired the old coherence-metric vocabulary from the public front-door documentation.

Selective Reverification does not discover dependencies or grant permission. The receiver owns the dependency declaration; the existing Receipt Gate still issues the signed `COMMIT`, `QUARANTINE`, or `DENY` disposition.

## 0.4.0 — 2026-08-21

- Added `openline-check`, an opinionated one-command front door over the existing Evidence Gateway and Receipt Gate.
- Added a reusable composite GitHub Action that fails CI on any disposition other than `COMMIT`.
- Added human-readable proof cards alongside machine-readable result JSON and signed decision receipts.
- Added explicit remediation text for stale, missing, untrusted, mismatched, and unsupported evidence.
- Added pinned-file, environment-provided, and explicitly disclosed ephemeral gate-key modes.
- Restricted the first `openline-check` profile to native `olp.source.v1` receipts rather than silently assigning semantics to arbitrary trace JSON.
- Added path-containment and artifact-size limits to the check-pack surface.
- Added eight adversarial front-door tests covering current evidence, stale review, missing evidence, untrusted producer, tampering, path escape, ephemeral authority, and GitHub Step Summary output.

`openline-check` does not create a new verifier or trust model. It is a product surface over the existing receiver-owned gate. `COMMIT` remains local to the receiver policy and gate identity that produced it.

## 0.3.1 — 2026-07-17

- Replaced recursive canonical-value validation with an explicit iterative stack.
- Added fixed canonical JSON limits of 128 levels and 100,000 nodes.
- Converted parser recursion failures into `CanonicalJSONError` so hostile input fails closed instead of escaping as `RecursionError`.
- Added regression tests for `loads`, `EvidenceGateway`, claim support, `ReceiptGate`, native chain verification, and the mapped adapter.
- Restricted JSON Pointer array indexes to ASCII digits and rejected oversized indexes before integer conversion.
- Expanded the suite from 32 to 44 tests.

Security: v0.3.0 is superseded. A deeply nested unauthenticated JSON artifact could crash every ingestion path before signature verification.

## 0.3.0 — 2026-07-17

- Added bounded native receipt-chain verification with parent, sequence, issuer, run, size, and trust checks.
- Added `olp.handoff.v1` full projections and compact JSONL prompt handoffs.
- Required valid pinned gate decisions and exact receiver policy-hash allowlists before facts can enter a handoff.
- Excluded sources with conflicting eligible non-commit decisions.
- Kept arbitrary source-authored claims out of the prompt projection while retaining them in the full audit object.
- Added `verify-chain`, `handoff`, and `benchmark` CLI commands.
- Added a three-track benchmark with explicit break-even reporting and nine hostile disposition fixtures.
- Added manifest, decision, fact, claim, chain, and aggregate byte limits.
- Added a handoff schema, conformance case, runnable example, adoption guide, benchmark methodology, and CI benchmark artifact.

The benchmark reports token cost, stored bytes, latency, allocation, and decision correctness separately. It does not claim improved LLM output quality.

## 0.2.0 — 2026-07-17

- Added receiver-owned bounded claim-support replay.
- Added the perfectly signed but unsupported hostile control.
- Added a declarative adapter for Ed25519-signed canonical JSON receipts.
- Separated normalization from cryptographic integrity and provenance.
- Added source-size protection, packaged schemas, conformance runner, clean-wheel CI, and adopter documentation.
- Expanded decision verification to cover the new assessment set and gate-ID binding.

Policy files from 0.1.0 must add `claim_rules`. An empty list is intentionally undecidable.

## 0.1.0 — 2026-07-17

- Initial native source receipt, Evidence Gateway, Receipt Gate, five dispositions, and receiver decision verification.
