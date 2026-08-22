from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from openline_lite.canonical import pretty, sha256_hex
from openline_lite.check import run_check
from openline_lite.continuity import analyze_continuity
from openline_lite.crypto import public_key_hex
from openline_lite.wire import SOURCE_SCHEMA, issue_source_receipt

PRODUCER_KEY = "01" * 32
GATE_KEY = "02" * 32


def continuity(changed: list[str]) -> dict[str, object]:
    return {
        "schema": "openline.continuity.v1",
        "claims": [
            "tests-standing",
            "review-standing",
            "merge-ready",
        ],
        "edges": [
            ["artifact:patch", "tests-standing"],
            ["tests-standing", "merge-ready"],
            ["artifact:review", "review-standing"],
        ],
        "changed": changed,
        "required_claims": [
            "tests-standing",
            "review-standing",
        ],
        "evidence_bindings": {
            "tests-standing": ["tests"],
            "review-standing": ["review"],
        },
    }


class SelectiveReverificationTests(unittest.TestCase):
    def make_case(
        self,
        root: Path,
        *,
        changed: list[str] | None,
    ) -> Path:
        evidence = root / "evidence"
        evidence.mkdir()
        tests_bytes = b'{"commit":"abc123","passed":true}'
        review_bytes = b'{"approved":true,"commit":"abc123"}'
        (evidence / "tests.json").write_bytes(tests_bytes)
        (evidence / "review.json").write_bytes(review_bytes)

        payload = {
            "schema": SOURCE_SCHEMA,
            "issuer": "coding-agent",
            "issued_at": "2026-08-21T17:55:00Z",
            "run_id": "run-481",
            "sequence": 0,
            "action": {
                "type": "merge_code",
                "name": "merge PR #481",
                "target": "abc123",
            },
            "claim": "Current patch has passing tests and current review approval.",
            "evidence": [
                {
                    "id": "tests",
                    "sha256": sha256_hex(tests_bytes),
                    "media_type": "application/json",
                },
                {
                    "id": "review",
                    "sha256": sha256_hex(review_bytes),
                    "media_type": "application/json",
                },
            ],
        }
        receipt = issue_source_receipt(payload, PRODUCER_KEY, "agent-key")
        (root / "source.receipt.json").write_text(pretty(receipt))
        (root / "producer-trust.json").write_text(
            pretty({"agent-key": public_key_hex(PRODUCER_KEY)})
        )
        policy = {
            "policy_id": "merge-current-evidence",
            "version": "1",
            "allowed_actions": ["merge_code"],
            "required_evidence": ["tests", "review"],
            "claim_rules": [
                {
                    "id": "tests-pass",
                    "evidence_id": "tests",
                    "pointer": "/passed",
                    "expected": True,
                },
                {
                    "id": "tests-current",
                    "evidence_id": "tests",
                    "pointer": "/commit",
                    "expected": "abc123",
                },
                {
                    "id": "review-approved",
                    "evidence_id": "review",
                    "pointer": "/approved",
                    "expected": True,
                },
                {
                    "id": "review-current",
                    "evidence_id": "review",
                    "pointer": "/commit",
                    "expected": "abc123",
                },
            ],
            "max_age_seconds": 3600,
            "on_undecidable": "QUARANTINE",
            "rollback_supported": False,
        }
        (root / "receiver-policy.json").write_text(pretty(policy))

        pack: dict[str, object] = {
            "schema": "openline.check.v1",
            "label": "Merge PR #481",
            "source": "source.receipt.json",
            "producer_trust": "producer-trust.json",
            "policy": "receiver-policy.json",
            "evidence": {
                "tests": "evidence/tests.json",
                "review": "evidence/review.json",
            },
            "now": "2026-08-21T18:00:00Z",
        }
        if changed is not None:
            pack["continuity"] = continuity(changed)
        (root / "check.json").write_text(pretty(pack))
        (root / "gate.key").write_text(GATE_KEY + "\n")
        return root / "check.json"

    def run_case(self, root: Path, changed: list[str] | None):
        return run_check(
            self.make_case(root, changed=changed),
            gate_key_path=str(root / "gate.key"),
            gate_id="test-gate",
            output_dir=root / "out",
        )

    def test_patch_change_reopens_only_test_standing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_case(Path(temporary), ["artifact:patch"])
            selective = result.result["selective_reverification"]
            self.assertEqual(result.decision, "QUARANTINE")
            self.assertEqual(selective["blocked_evidence"], ["tests"])
            self.assertEqual(
                selective["reopened_required_claims"],
                ["tests-standing"],
            )
            self.assertIn("review-standing", selective["retained_claims"])
            self.assertIn("merge-ready", selective["reopened_claims"])
            self.assertIn("Reverification required:", result.proof_card)

    def test_review_change_withholds_review_not_tests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_case(Path(temporary), ["artifact:review"])
            selective = result.result["selective_reverification"]
            self.assertEqual(result.decision, "QUARANTINE")
            self.assertEqual(selective["blocked_evidence"], ["review"])
            self.assertIn("tests-standing", selective["retained_claims"])

    def test_unrelated_change_preserves_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_case(Path(temporary), ["artifact:readme"])
            selective = result.result["selective_reverification"]
            self.assertEqual(result.decision, "COMMIT")
            self.assertEqual(selective["blocked_evidence"], [])
            self.assertEqual(selective["reopened_claims"], [])

    def test_absent_continuity_is_backward_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_case(Path(temporary), None)
            self.assertEqual(result.decision, "COMMIT")
            self.assertIsNone(result.result["selective_reverification"])

    def test_cycle_is_bounded(self) -> None:
        value = continuity(["artifact:patch"])
        value["edges"] = [
            ["artifact:patch", "tests-standing"],
            ["tests-standing", "merge-ready"],
            ["merge-ready", "tests-standing"],
        ]
        result = analyze_continuity(
            value,
            evidence_ids=frozenset({"tests", "review"}),
        )
        self.assertEqual(
            set(result.reopened_claims),
            {"tests-standing", "merge-ready"},
        )

    def test_unknown_evidence_binding_fails_closed(self) -> None:
        value = continuity(["artifact:patch"])
        value["evidence_bindings"]["tests-standing"] = ["missing"]
        with self.assertRaisesRegex(
            ValueError,
            "continuity_binding_unknown_evidence",
        ):
            analyze_continuity(
                value,
                evidence_ids=frozenset({"tests", "review"}),
            )


if __name__ == "__main__":
    unittest.main()
