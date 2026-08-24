from __future__ import annotations

import hashlib
import json
import unittest

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


def source(private_key: str, evidence: list[dict[str, str]]) -> dict:
    payload = {
        "schema": "olp.source.v1",
        "issuer": "producer",
        "issued_at": "2026-08-24T00:00:00Z",
        "run_id": "impact-test",
        "sequence": 0,
        "parent_hash": None,
        "action": {"type": "deploy", "name": "ship", "target": "api"},
        "claim": "fixture",
        "evidence": evidence,
    }
    return issue_source_receipt(payload, private_key, "producer")


def decision(
    gate_private: str,
    source_bytes: bytes,
    required: list[str],
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
    names = (
        "integrity",
        "provenance",
        "normalization",
        "policy",
        "freshness",
        "evidence",
        "claim_support",
    )
    statuses = {
        name: {"status": "pass", "reason_codes": [], "details": {}}
        for name in names
    }
    payload = {
        "schema": "olp.decision.v1",
        "gate_id": "gate",
        "issued_at": "2026-08-24T00:01:00Z",
        "source_format": "olp.source.v1",
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "policy": {**policy.to_dict(), "sha256": policy.sha256},
        "verdict": "VERIFIED",
        "decision": "COMMIT",
        "reason_codes": [],
        "side_effect_observed": False,
        "assessments": statuses,
    }
    return issue_decision_receipt(payload, gate_private, "gate")


def fixture(
    required: list[str],
    completeness: str = COMPLETE,
):
    producer_key = generate_private_key_hex()
    gate_key = generate_private_key_hex()
    evidence = [
        {"id": "a", "sha256": E1},
        {"id": "b", "sha256": E2},
        {"id": "extra", "sha256": EXTRA},
    ]
    source_receipt = source(producer_key, evidence)
    source_bytes = pretty(source_receipt).encode()
    decision_receipt = decision(gate_key, source_bytes, required)
    decision_bytes = pretty(decision_receipt).encode()
    bound = bind_verified_decision(
        decision_receipt_bytes=decision_bytes,
        source_receipt_bytes=source_bytes,
        trusted_gate_keys={"gate": public_key_hex(gate_key)},
        trusted_producer_keys={"producer": public_key_hex(producer_key)},
        binding_completeness=completeness,
        label="fixture",
    )
    return bound, decision_bytes, source_bytes, gate_key, producer_key


class ImpactTests(unittest.TestCase):
    def test_required_evidence_reopens(self):
        bound, *_ = fixture(["a"])
        result = evaluate_impact(build_impact_index([bound]), [E1])
        self.assertEqual(result.reopen, (bound.decision_id,))
        self.assertEqual(result.retain, ())
        self.assertEqual(result.undetermined, ())

    def test_unrelated_required_evidence_retains_when_complete(self):
        bound, *_ = fixture(["a"], COMPLETE)
        result = evaluate_impact(build_impact_index([bound]), [E2])
        self.assertEqual(result.retain, (bound.decision_id,))

    def test_incomplete_binding_never_silently_retains(self):
        bound, *_ = fixture(["a"], INCOMPLETE)
        result = evaluate_impact(build_impact_index([bound]), [E2])
        self.assertEqual(result.undetermined, (bound.decision_id,))
        self.assertEqual(result.retain, ())

    def test_incomplete_binding_still_reopens_known_match(self):
        bound, *_ = fixture(["a"], INCOMPLETE)
        result = evaluate_impact(build_impact_index([bound]), [E1])
        self.assertEqual(result.reopen, (bound.decision_id,))

    def test_non_required_colocated_artifact_does_not_expand_boundary(self):
        bound, *_ = fixture(["a"], COMPLETE)
        self.assertNotIn(EXTRA, bound.evidence_sha256)
        result = evaluate_impact(build_impact_index([bound]), [EXTRA])
        self.assertEqual(result.retain, (bound.decision_id,))

    def test_multiple_required_bindings(self):
        bound, *_ = fixture(["a", "b"])
        self.assertEqual(set(bound.evidence_sha256), {E1, E2})
        result = evaluate_impact(build_impact_index([bound]), [E2])
        self.assertEqual(result.reopen, (bound.decision_id,))

    def test_exact_source_bytes_are_bound(self):
        _, decision_bytes, source_bytes, gate_key, producer_key = fixture(["a"])
        altered = source_bytes + b"\n"
        with self.assertRaisesRegex(ValueError, "decision_source_bytes_mismatch"):
            bind_verified_decision(
                decision_receipt_bytes=decision_bytes,
                source_receipt_bytes=altered,
                trusted_gate_keys={"gate": public_key_hex(gate_key)},
                trusted_producer_keys={
                    "producer": public_key_hex(producer_key),
                },
                binding_completeness=COMPLETE,
            )

    def test_untrusted_gate_fails(self):
        _, decision_bytes, source_bytes, _, producer_key = fixture(["a"])
        with self.assertRaisesRegex(ValueError, "decision_receipt_invalid"):
            bind_verified_decision(
                decision_receipt_bytes=decision_bytes,
                source_receipt_bytes=source_bytes,
                trusted_gate_keys={},
                trusted_producer_keys={
                    "producer": public_key_hex(producer_key),
                },
                binding_completeness=COMPLETE,
            )

    def test_untrusted_producer_fails(self):
        _, decision_bytes, source_bytes, gate_key, _ = fixture(["a"])
        with self.assertRaisesRegex(ValueError, "source_key_untrusted"):
            bind_verified_decision(
                decision_receipt_bytes=decision_bytes,
                source_receipt_bytes=source_bytes,
                trusted_gate_keys={"gate": public_key_hex(gate_key)},
                trusted_producer_keys={},
                binding_completeness=COMPLETE,
            )

    def test_tampered_decision_fails(self):
        _, decision_bytes, source_bytes, gate_key, producer_key = fixture(["a"])
        value = json.loads(decision_bytes)
        value["payload"]["decision"] = "DENY"
        tampered = pretty(value).encode()
        with self.assertRaisesRegex(ValueError, "decision_receipt_invalid"):
            bind_verified_decision(
                decision_receipt_bytes=tampered,
                source_receipt_bytes=source_bytes,
                trusted_gate_keys={"gate": public_key_hex(gate_key)},
                trusted_producer_keys={
                    "producer": public_key_hex(producer_key),
                },
                binding_completeness=COMPLETE,
            )

    def test_duplicate_decision_rejected(self):
        bound, *_ = fixture(["a"])
        with self.assertRaisesRegex(ValueError, "impact_decision_duplicate"):
            build_impact_index([bound, bound])

    def test_index_is_deterministic(self):
        bound, *_ = fixture(["a"])
        first = build_impact_index([bound]).index_sha256
        second = build_impact_index([bound]).index_sha256
        self.assertEqual(first, second)

    def test_invalidation_duplicates_rejected(self):
        bound, *_ = fixture(["a"])
        index = build_impact_index([bound])
        with self.assertRaisesRegex(ValueError, "impact_invalidation_duplicate"):
            evaluate_impact(index, [E1, E1])

    def test_invalid_hash_rejected(self):
        bound, *_ = fixture(["a"])
        index = build_impact_index([bound])
        with self.assertRaisesRegex(ValueError, "impact_invalidation_hash_invalid"):
            evaluate_impact(index, ["not-a-hash"])

    def test_empty_invalidation_rejected(self):
        bound, *_ = fixture(["a"])
        index = build_impact_index([bound])
        with self.assertRaisesRegex(ValueError, "impact_invalidation_empty"):
            evaluate_impact(index, [])

    def test_empty_index_rejected(self):
        with self.assertRaisesRegex(ValueError, "impact_index_empty"):
            build_impact_index([])

    def test_result_hash_is_deterministic(self):
        bound, *_ = fixture(["a"])
        index = build_impact_index([bound])
        first = evaluate_impact(index, [E1]).result_sha256
        second = evaluate_impact(index, [E1]).result_sha256
        self.assertEqual(first, second)

    def test_partition_is_exhaustive(self):
        first, *_ = fixture(["a"], COMPLETE)
        second, *_ = fixture(["b"], INCOMPLETE)
        index = build_impact_index([first, second])
        result = evaluate_impact(index, [E1])
        reopen = set(result.reopen)
        retain = set(result.retain)
        undetermined = set(result.undetermined)
        partition = reopen | retain | undetermined
        self.assertEqual(partition, {first.decision_id, second.decision_id})
        self.assertFalse(reopen & retain)
        self.assertFalse(reopen & undetermined)
        self.assertFalse(retain & undetermined)


if __name__ == "__main__":
    unittest.main()
