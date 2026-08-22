"""Receiver-owned selective reverification for OpenLine Check.

This module does one thing: determine which previously standing claims are
exposed by declared state changes. It does not authorize execution.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Mapping

CONTINUITY_SCHEMA = "openline.continuity.v1"
MAX_CLAIMS = 1_024
MAX_EDGES = 4_096
MAX_CHANGED_ROOTS = 1_024


@dataclass(frozen=True)
class ContinuityResult:
    changed_roots: tuple[str, ...]
    reopened_claims: tuple[str, ...]
    retained_claims: tuple[str, ...]
    reopened_required_claims: tuple[str, ...]
    blocked_evidence: tuple[str, ...]
    paths: Mapping[str, tuple[str, ...]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "openline.selective-reverification-result.v1",
            "changed_roots": list(self.changed_roots),
            "reopened_claims": list(self.reopened_claims),
            "retained_claims": list(self.retained_claims),
            "reopened_required_claims": list(self.reopened_required_claims),
            "blocked_evidence": list(self.blocked_evidence),
            "paths": {claim: list(path) for claim, path in sorted(self.paths.items())},
            "policy_authority": "receiver_owned",
            "runtime_permission": "NONE",
        }


def _string_list(
    value: object,
    *,
    label: str,
    maximum: int,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"continuity_{label}_invalid")
    if len(value) > maximum:
        raise ValueError(f"continuity_{label}_limit_exceeded")
    if not allow_empty and not value:
        raise ValueError(f"continuity_{label}_empty")
    if not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"continuity_{label}_invalid")
    if len(set(value)) != len(value):
        raise ValueError(f"continuity_{label}_duplicate")
    return tuple(value)


def _validate(
    value: Mapping[str, Any],
    *,
    evidence_ids: frozenset[str],
) -> tuple[
    tuple[str, ...],
    tuple[tuple[str, str], ...],
    tuple[str, ...],
    tuple[str, ...],
    dict[str, tuple[str, ...]],
]:
    required = {
        "schema",
        "claims",
        "edges",
        "changed",
        "required_claims",
        "evidence_bindings",
    }
    unknown = set(value) - required
    missing = required - set(value)
    if missing:
        raise ValueError("continuity_missing:" + ",".join(sorted(missing)))
    if unknown:
        raise ValueError("continuity_unknown:" + ",".join(sorted(unknown)))
    if value["schema"] != CONTINUITY_SCHEMA:
        raise ValueError("continuity_schema_unsupported")

    claims = _string_list(
        value["claims"],
        label="claims",
        maximum=MAX_CLAIMS,
        allow_empty=False,
    )
    changed = _string_list(
        value["changed"],
        label="changed",
        maximum=MAX_CHANGED_ROOTS,
    )
    required_claims = _string_list(
        value["required_claims"],
        label="required_claims",
        maximum=MAX_CLAIMS,
    )
    claim_set = frozenset(claims)
    if not set(required_claims) <= claim_set:
        raise ValueError("continuity_required_claim_unknown")

    raw_edges = value["edges"]
    if not isinstance(raw_edges, list):
        raise ValueError("continuity_edges_invalid")
    if len(raw_edges) > MAX_EDGES:
        raise ValueError("continuity_edges_limit_exceeded")
    edges: list[tuple[str, str]] = []
    for edge in raw_edges:
        if (
            not isinstance(edge, list)
            or len(edge) != 2
            or not all(isinstance(item, str) and item for item in edge)
        ):
            raise ValueError("continuity_edge_invalid")
        edges.append((edge[0], edge[1]))

    raw_bindings = value["evidence_bindings"]
    if not isinstance(raw_bindings, dict):
        raise ValueError("continuity_evidence_bindings_invalid")
    if set(raw_bindings) != set(required_claims):
        raise ValueError("continuity_required_binding_mismatch")

    bindings: dict[str, tuple[str, ...]] = {}
    for claim in required_claims:
        bound = _string_list(
            raw_bindings[claim],
            label="evidence_binding",
            maximum=256,
            allow_empty=False,
        )
        if not set(bound) <= evidence_ids:
            raise ValueError(f"continuity_binding_unknown_evidence:{claim}")
        bindings[claim] = bound

    return claims, tuple(edges), changed, required_claims, bindings


def analyze_continuity(
    value: Mapping[str, Any],
    *,
    evidence_ids: frozenset[str],
) -> ContinuityResult:
    """Compute dependency-aware selective reopening.

    The receiver supplies the graph. Changed roots are traversed through that
    graph. Only receiver-declared required claims can suppress inherited
    evidence, and every required claim must be explicitly bound to evidence.
    """
    if not isinstance(value, Mapping):
        raise ValueError("continuity_invalid")

    (
        claims,
        edges,
        changed,
        required_claims,
        bindings,
    ) = _validate(value, evidence_ids=evidence_ids)

    claim_set = frozenset(claims)
    adjacency: dict[str, list[str]] = defaultdict(list)
    for source, target in edges:
        adjacency[source].append(target)

    queue = deque(changed)
    seen = set(changed)
    predecessor: dict[str, str | None] = {root: None for root in changed}
    reopened = {root for root in changed if root in claim_set}

    while queue:
        source = queue.popleft()
        for target in adjacency.get(source, ()):
            if target in seen:
                continue
            seen.add(target)
            predecessor[target] = source
            queue.append(target)
            if target in claim_set:
                reopened.add(target)

    required_set = frozenset(required_claims)
    reopened_required = reopened & required_set
    blocked = {
        evidence_id for claim in reopened_required for evidence_id in bindings[claim]
    }

    paths: dict[str, tuple[str, ...]] = {}
    for claim in sorted(reopened):
        path = [claim]
        cursor = claim
        while predecessor.get(cursor) is not None:
            cursor = predecessor[cursor]  # type: ignore[assignment]
            path.append(cursor)
        paths[claim] = tuple(reversed(path))

    return ContinuityResult(
        changed_roots=tuple(sorted(changed)),
        reopened_claims=tuple(sorted(reopened)),
        retained_claims=tuple(sorted(claim_set - reopened)),
        reopened_required_claims=tuple(sorted(reopened_required)),
        blocked_evidence=tuple(sorted(blocked)),
        paths=paths,
    )
