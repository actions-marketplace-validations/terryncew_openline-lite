from __future__ import annotations

import json
import pytest

from openline_lite.canonical import pretty
from openline_lite.crypto import generate_private_key_hex, public_key_hex
from openline_lite.impact import (
    COMPLETE,
    INCOMPLETE,
    bind_verified_decision,
    build_impact_index,
    evaluate_impact,
)
from openline_lite.policy import Policy
from openline_lite.wire import issue_decision_receipt, issue_source_receipt


E1 = "11" * 32
E2 = "22" * 32
EXTRA = "33" * 32
BAD = "44" * 32


def source(private_key: str, evidence: list[dict[str, str]]) -> dict:
    return issue_source_receipt(
        {
            "schema": "olp.source.v1",
            "issuer": "producer",
            "issued_at": "2026-08-24T00:00:00Z",
            "run_id": "impact-test",
            "sequence": 0,
            "parent_hash": None,
            "action": {"type": "deploy", "name": "ship", "target": "api"},
            "claim": "fixture",
            "evidence": evidence,
        },
        private_key,
        "producer",
    )


def decision(
    gate_private: str,
    source_bytes: bytes,
    required: list[str],
    *,
    verdict: str = "VERIFIED",
    disposition: str = "COMMIT",
) -> dict:
    policy = Policy.from_mapping(
        {
            "policy_id": "impact",
            "version": "1",
            "allowed_actions": ["deploy"],
            "required_evidence": required,
            "claim_rules": [],
            "max_age_seconds": 3600,
            "on_undecidable": "QUARANTINE",
            "rollback_supported": False,
        }
    )
    statuses = {
        name: {"status": "pass", "reason_codes": [], "details": {}}
        for name in (
            "integrity",
            "provenance",
            "normalization",
            "policy",
            "freshness",
            "evidence",
            "claim_support",
        )
    }
    return issue_decision_receipt(
        {
            "schema": "olp.decision.v1",
            "gate_id": "gate",
            "issued_at": "2026-08-24T00:01:00Z",
            "source_format": "olp.source.v1",
            "source_sha256": __import__("hashlib").sha256(source_bytes).hexdigest(),
            "policy": {**policy.to_dict(), "sha256": policy.sha256},
            "verdict": verdict,
            "decision": disposition,
            "reason_codes": [],
            "side_effect_observed": False,
            "assessments": statuses,
        },
        gate_private,
        "gate",
    )


def fixture(required: list[str], completeness: str = COMPLETE):
    producer_key = generate_private_key_hex()
    gate_key = generate_private_key_hex()
    sr = source(
        producer_key,
        [
            {"id": "a", "sha256": E1},
            {"id": "b", "sha256": E2},
            {"id": "extra", "sha256": EXTRA},
        ],
    )
    sb = pretty(sr).encode()
    dr = decision(gate_key, sb, required)
    db = pretty(dr).encode()
    bound = bind_verified_decision(
        decision_receipt_bytes=db,
        source_receipt_bytes=sb,
        trusted_gate_keys={"gate": public_key_hex(gate_key)},
        trusted_producer_keys={"producer": public_key_hex(producer_key)},
        binding_completeness=completeness,
        label="fixture",
    )
    return bound, db, sb, gate_key, producer_key


def test_required_evidence_reopens():
    bound, *_ = fixture(["a"])
    result = evaluate_impact(build_impact_index([bound]), [E1])
    assert result.reopen == (bound.decision_id,)
    assert result.retain == ()
    assert result.undetermined == ()


def test_unrelated_required_evidence_retains_when_complete():
    bound, *_ = fixture(["a"], COMPLETE)
    result = evaluate_impact(build_impact_index([bound]), [E2])
    assert result.retain == (bound.decision_id,)


def test_incomplete_binding_never_silently_retains():
    bound, *_ = fixture(["a"], INCOMPLETE)
    result = evaluate_impact(build_impact_index([bound]), [E2])
    assert result.undetermined == (bound.decision_id,)
    assert result.retain == ()


def test_incomplete_binding_still_reopens_known_match():
    bound, *_ = fixture(["a"], INCOMPLETE)
    result = evaluate_impact(build_impact_index([bound]), [E1])
    assert result.reopen == (bound.decision_id,)


def test_non_required_colocated_artifact_does_not_expand_boundary():
    bound, *_ = fixture(["a"], COMPLETE)
    assert EXTRA not in bound.evidence_sha256
    result = evaluate_impact(build_impact_index([bound]), [EXTRA])
    assert result.retain == (bound.decision_id,)


def test_multiple_required_bindings():
    bound, *_ = fixture(["a", "b"])
    assert set(bound.evidence_sha256) == {E1, E2}
    result = evaluate_impact(build_impact_index([bound]), [E2])
    assert result.reopen == (bound.decision_id,)


def test_exact_source_bytes_are_bound():
    bound, db, sb, gate_key, producer_key = fixture(["a"])
    altered = sb + b"\n"
    with pytest.raises(ValueError, match="decision_source_bytes_mismatch"):
        bind_verified_decision(
            decision_receipt_bytes=db,
            source_receipt_bytes=altered,
            trusted_gate_keys={"gate": public_key_hex(gate_key)},
            trusted_producer_keys={"producer": public_key_hex(producer_key)},
            binding_completeness=COMPLETE,
        )


def test_untrusted_gate_fails():
    bound, db, sb, gate_key, producer_key = fixture(["a"])
    with pytest.raises(ValueError, match="decision_receipt_invalid"):
        bind_verified_decision(
            decision_receipt_bytes=db,
            source_receipt_bytes=sb,
            trusted_gate_keys={},
            trusted_producer_keys={"producer": public_key_hex(producer_key)},
            binding_completeness=COMPLETE,
        )


def test_untrusted_producer_fails():
    bound, db, sb, gate_key, producer_key = fixture(["a"])
    with pytest.raises(ValueError, match="source_key_untrusted"):
        bind_verified_decision(
            decision_receipt_bytes=db,
            source_receipt_bytes=sb,
            trusted_gate_keys={"gate": public_key_hex(gate_key)},
            trusted_producer_keys={},
            binding_completeness=COMPLETE,
        )


def test_tampered_decision_fails():
    bound, db, sb, gate_key, producer_key = fixture(["a"])
    value = json.loads(db)
    value["payload"]["decision"] = "DENY"
    tampered = pretty(value).encode()
    with pytest.raises(ValueError, match="decision_receipt_invalid"):
        bind_verified_decision(
            decision_receipt_bytes=tampered,
            source_receipt_bytes=sb,
            trusted_gate_keys={"gate": public_key_hex(gate_key)},
            trusted_producer_keys={"producer": public_key_hex(producer_key)},
            binding_completeness=COMPLETE,
        )


def test_duplicate_decision_rejected():
    bound, *_ = fixture(["a"])
    with pytest.raises(ValueError, match="impact_decision_duplicate"):
        build_impact_index([bound, bound])


def test_index_is_deterministic():
    a, *_ = fixture(["a"])
    # Same object twice is duplicate, so compare repeated builds.
    assert build_impact_index([a]).index_sha256 == build_impact_index([a]).index_sha256


def test_invalidation_duplicates_rejected():
    bound, *_ = fixture(["a"])
    with pytest.raises(ValueError, match="impact_invalidation_duplicate"):
        evaluate_impact(build_impact_index([bound]), [E1, E1])


def test_invalid_hash_rejected():
    bound, *_ = fixture(["a"])
    with pytest.raises(ValueError, match="impact_invalidation_hash_invalid"):
        evaluate_impact(build_impact_index([bound]), ["not-a-hash"])


def test_empty_invalidation_rejected():
    bound, *_ = fixture(["a"])
    with pytest.raises(ValueError, match="impact_invalidation_empty"):
        evaluate_impact(build_impact_index([bound]), [])


def test_empty_index_rejected():
    with pytest.raises(ValueError, match="impact_index_empty"):
        build_impact_index([])


def test_result_hash_is_deterministic():
    bound, *_ = fixture(["a"])
    index = build_impact_index([bound])
    assert evaluate_impact(index, [E1]).result_sha256 == evaluate_impact(
        index, [E1]
    ).result_sha256


def test_partition_is_exhaustive():
    a, *_ = fixture(["a"], COMPLETE)
    b, *_ = fixture(["b"], INCOMPLETE)
    index = build_impact_index([a, b])
    result = evaluate_impact(index, [E1])
    partition = set(result.reopen) | set(result.retain) | set(result.undetermined)
    assert partition == {a.decision_id, b.decision_id}
    assert not (set(result.reopen) & set(result.retain))
    assert not (set(result.reopen) & set(result.undetermined))
    assert not (set(result.retain) & set(result.undetermined))
