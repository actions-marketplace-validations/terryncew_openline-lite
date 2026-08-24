"""Decision-bound trust boundary index.

This module turns already verified, receiver-signed COMMIT receipts into a
flat reverse index from evidence hashes to standing decisions.

It does not discover invalidations, authorize execution, or infer missing
dependencies. A decision can be RETAINED only when its receiver-declared
binding is complete and none of the invalidated evidence hashes appear in
that frozen binding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .canonical import loads, object_hash, sha256_hex
from .wire import (
    SOURCE_SCHEMA,
    envelope_hash,
    inspect_envelope,
    validate_source_payload,
    verify_decision_receipt,
)

IMPACT_INDEX_SCHEMA = "openline.impact-index.v1"
IMPACT_RESULT_SCHEMA = "openline.impact-result.v1"
MAX_DECISIONS = 4_096
MAX_EVIDENCE_PER_DECISION = 256
MAX_INVALIDATIONS = 1_024
COMPLETE = "COMPLETE"
INCOMPLETE = "INCOMPLETE"
REOPEN = "REOPEN"
RETAIN = "RETAIN"
UNDETERMINED = "UNDETERMINED"


@dataclass(frozen=True)
class BoundDecision:
    decision_id: str
    decision_receipt_sha256: str
    source_sha256: str
    gate_id: str
    policy_sha256: str
    evidence_sha256: tuple[str, ...]
    binding_completeness: str
    label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "decision_id": self.decision_id,
            "decision_receipt_sha256": self.decision_receipt_sha256,
            "source_sha256": self.source_sha256,
            "gate_id": self.gate_id,
            "policy_sha256": self.policy_sha256,
            "evidence_sha256": list(self.evidence_sha256),
            "binding_completeness": self.binding_completeness,
        }
        if self.label is not None:
            value["label"] = self.label
        return value


@dataclass(frozen=True)
class ImpactIndex:
    decisions: tuple[BoundDecision, ...]
    reverse_index: Mapping[str, tuple[str, ...]]
    index_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": IMPACT_INDEX_SCHEMA,
            "decisions": [decision.to_dict() for decision in self.decisions],
            "reverse_index": {
                evidence: list(decisions)
                for evidence, decisions in sorted(self.reverse_index.items())
            },
            "index_sha256": self.index_sha256,
            "policy_authority": "receiver_owned",
            "runtime_permission": "NONE",
        }


@dataclass(frozen=True)
class ImpactResult:
    invalidated_evidence_sha256: tuple[str, ...]
    reopen: tuple[str, ...]
    retain: tuple[str, ...]
    undetermined: tuple[str, ...]
    matched_evidence: Mapping[str, tuple[str, ...]]
    index_sha256: str
    result_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": IMPACT_RESULT_SCHEMA,
            "invalidated_evidence_sha256": list(self.invalidated_evidence_sha256),
            "reopen": list(self.reopen),
            "retain": list(self.retain),
            "undetermined": list(self.undetermined),
            "matched_evidence": {
                decision: list(evidence)
                for decision, evidence in sorted(self.matched_evidence.items())
            },
            "index_sha256": self.index_sha256,
            "result_sha256": self.result_sha256,
            "policy_authority": "receiver_owned",
            "runtime_permission": "NONE",
        }


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        return len(bytes.fromhex(value)) == 32
    except ValueError:
        return False


def _parse_object(data: bytes, label: str) -> dict[str, Any]:
    value = loads(data)
    if not isinstance(value, dict):
        raise ValueError(f"{label}_object_required")
    return value


def _verify_source_receipt(
    source_bytes: bytes,
    *,
    trusted_producer_keys: Mapping[str, str],
) -> dict[str, Any]:
    receipt = _parse_object(source_bytes, "source_receipt")
    inspected = inspect_envelope(receipt)
    errors = list(inspected["errors"])
    payload = inspected["payload"]
    try:
        validate_source_payload(payload)
    except (TypeError, ValueError) as exc:
        errors.append(str(exc))

    if payload.get("schema") != SOURCE_SCHEMA:
        errors.append("source_schema_unsupported")
    key_id = str(inspected.get("key_id") or "")
    issuer = payload.get("issuer")
    if issuer != key_id:
        errors.append("source_issuer_key_id_mismatch")
    expected_key = trusted_producer_keys.get(key_id)
    if expected_key is None:
        errors.append("source_key_untrusted")
    elif expected_key != inspected.get("public_key"):
        errors.append("source_key_mismatch")

    if errors:
        raise ValueError("source_receipt_invalid:" + ",".join(sorted(set(errors))))
    return payload


def bind_verified_decision(
    *,
    decision_receipt_bytes: bytes,
    source_receipt_bytes: bytes,
    trusted_gate_keys: Mapping[str, str],
    trusted_producer_keys: Mapping[str, str],
    binding_completeness: str,
    label: str | None = None,
) -> BoundDecision:
    """Bind one standing COMMIT decision to the exact evidence hashes it required."""
    if binding_completeness not in {COMPLETE, INCOMPLETE}:
        raise ValueError("binding_completeness_invalid")
    if label is not None and (not isinstance(label, str) or not label.strip()):
        raise ValueError("binding_label_invalid")

    decision_receipt = _parse_object(decision_receipt_bytes, "decision_receipt")
    verified = verify_decision_receipt(decision_receipt, trusted_gate_keys)
    if not verified["valid"]:
        reasons = ",".join(verified["errors"])
        raise ValueError(f"decision_receipt_invalid:{reasons}")
    payload = verified["payload"]
    if payload.get("verdict") != "VERIFIED" or payload.get("decision") != "COMMIT":
        raise ValueError("decision_not_standing_commit")

    exact_source_hash = sha256_hex(source_receipt_bytes)
    if payload.get("source_sha256") != exact_source_hash:
        raise ValueError("decision_source_bytes_mismatch")

    source_payload = _verify_source_receipt(
        source_receipt_bytes,
        trusted_producer_keys=trusted_producer_keys,
    )

    policy = payload.get("policy")
    if not isinstance(policy, Mapping):
        raise ValueError("decision_policy_invalid")
    required = policy.get("required_evidence")
    if (
        not isinstance(required, list)
        or len(required) > MAX_EVIDENCE_PER_DECISION
        or not all(isinstance(item, str) and item for item in required)
    ):
        raise ValueError("decision_required_evidence_invalid")
    if len(set(required)) != len(required):
        raise ValueError("decision_required_evidence_duplicate")

    source_evidence = source_payload.get("evidence")
    if not isinstance(source_evidence, list):
        raise ValueError("source_evidence_invalid")
    commitments = {
        item["id"]: item["sha256"]
        for item in source_evidence
        if isinstance(item, Mapping)
        and isinstance(item.get("id"), str)
        and _is_sha256(item.get("sha256"))
    }
    missing = []
    for evidence_id in required:
        if evidence_id not in commitments:
            missing.append(evidence_id)
    if missing:
        raise ValueError("required_commitment_missing:" + ",".join(sorted(missing)))

    bound_hashes = {commitments[evidence_id] for evidence_id in required}
    evidence_hashes = tuple(sorted(bound_hashes))
    if len(evidence_hashes) > MAX_EVIDENCE_PER_DECISION:
        raise ValueError("decision_evidence_limit_exceeded")

    policy_hash = policy.get("sha256")
    if not _is_sha256(policy_hash):
        raise ValueError("decision_policy_hash_invalid")

    return BoundDecision(
        decision_id=envelope_hash(decision_receipt),
        decision_receipt_sha256=sha256_hex(decision_receipt_bytes),
        source_sha256=exact_source_hash,
        gate_id=str(payload["gate_id"]),
        policy_sha256=str(policy_hash),
        evidence_sha256=evidence_hashes,
        binding_completeness=binding_completeness,
        label=label.strip() if label is not None else None,
    )


def build_impact_index(decisions: Sequence[BoundDecision]) -> ImpactIndex:
    if not decisions:
        raise ValueError("impact_index_empty")
    if len(decisions) > MAX_DECISIONS:
        raise ValueError("impact_decision_limit_exceeded")

    by_id: dict[str, BoundDecision] = {}
    reverse: dict[str, set[str]] = {}
    for decision in decisions:
        if decision.decision_id in by_id:
            raise ValueError(f"impact_decision_duplicate:{decision.decision_id}")
        by_id[decision.decision_id] = decision
        for evidence_hash in decision.evidence_sha256:
            if not _is_sha256(evidence_hash):
                raise ValueError("impact_evidence_hash_invalid")
            reverse.setdefault(evidence_hash, set()).add(decision.decision_id)

    ordered = tuple(by_id[key] for key in sorted(by_id))
    reverse_frozen = {
        evidence: tuple(sorted(decision_ids))
        for evidence, decision_ids in sorted(reverse.items())
    }
    body = {
        "schema": IMPACT_INDEX_SCHEMA,
        "decisions": [decision.to_dict() for decision in ordered],
        "reverse_index": {
            evidence: list(decision_ids)
            for evidence, decision_ids in reverse_frozen.items()
        },
        "policy_authority": "receiver_owned",
        "runtime_permission": "NONE",
    }
    return ImpactIndex(
        decisions=ordered,
        reverse_index=reverse_frozen,
        index_sha256=object_hash(body),
    )


def evaluate_impact(
    index: ImpactIndex,
    invalidated_evidence_sha256: Sequence[str],
) -> ImpactResult:
    if not invalidated_evidence_sha256:
        raise ValueError("impact_invalidation_empty")
    if len(invalidated_evidence_sha256) > MAX_INVALIDATIONS:
        raise ValueError("impact_invalidation_limit_exceeded")
    invalidated = tuple(sorted(set(invalidated_evidence_sha256)))
    if len(invalidated) != len(invalidated_evidence_sha256):
        raise ValueError("impact_invalidation_duplicate")
    if not all(_is_sha256(item) for item in invalidated):
        raise ValueError("impact_invalidation_hash_invalid")

    impacted: dict[str, set[str]] = {}
    for evidence_hash in invalidated:
        for decision_id in index.reverse_index.get(evidence_hash, ()):
            impacted.setdefault(decision_id, set()).add(evidence_hash)

    reopen: list[str] = []
    retain: list[str] = []
    undetermined: list[str] = []
    for decision in index.decisions:
        if decision.decision_id in impacted:
            reopen.append(decision.decision_id)
        elif decision.binding_completeness == COMPLETE:
            retain.append(decision.decision_id)
        else:
            undetermined.append(decision.decision_id)

    matched = {
        decision_id: tuple(sorted(hashes))
        for decision_id, hashes in sorted(impacted.items())
    }
    body = {
        "schema": IMPACT_RESULT_SCHEMA,
        "invalidated_evidence_sha256": list(invalidated),
        "reopen": reopen,
        "retain": retain,
        "undetermined": undetermined,
        "matched_evidence": {
            decision: list(evidence)
            for decision, evidence in matched.items()
        },
        "index_sha256": index.index_sha256,
        "policy_authority": "receiver_owned",
        "runtime_permission": "NONE",
    }
    return ImpactResult(
        invalidated_evidence_sha256=invalidated,
        reopen=tuple(reopen),
        retain=tuple(retain),
        undetermined=tuple(undetermined),
        matched_evidence=matched,
        index_sha256=index.index_sha256,
        result_sha256=object_hash(body),
    )
