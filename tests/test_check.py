from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from openline_lite.canonical import pretty, sha256_hex
from openline_lite.check import CheckRun, run_check
from openline_lite.crypto import public_key_hex
from openline_lite.wire import SOURCE_SCHEMA, issue_source_receipt

PRODUCER_KEY = "01" * 32
GATE_KEY = "02" * 32


class OpenLineCheckTests(unittest.TestCase):
    def make_case(
        self,
        root: Path,
        *,
        review_commit: str = "abc123",
        include_review: bool = True,
        trust_producer: bool = True,
        tamper_tests_after_issue: bool = False,
    ) -> Path:
        evidence = root / "evidence"
        evidence.mkdir()
        tests_bytes = b'{"commit":"abc123","passed":true}'
        review_bytes = ('{"approved":true,"commit":"' + review_commit + '"}').encode()
        (evidence / "tests.json").write_bytes(tests_bytes)
        if include_review:
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
        source_receipt = issue_source_receipt(payload, PRODUCER_KEY, "agent-key")
        (root / "source.receipt.json").write_text(pretty(source_receipt))

        producer_trust = (
            {"agent-key": public_key_hex(PRODUCER_KEY)} if trust_producer else {}
        )
        (root / "producer-trust.json").write_text(pretty(producer_trust))

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

        pack = {
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
        (root / "check.json").write_text(pretty(pack))

        if tamper_tests_after_issue:
            (evidence / "tests.json").write_bytes(
                b'{"commit":"abc123","passed":false}'
            )
        return root / "check.json"

    def run_case(self, root: Path, **kwargs: Any) -> CheckRun:
        pack = self.make_case(root, **kwargs)
        gate_key = root / "gate.key"
        gate_key.write_text(GATE_KEY + "\n")
        return run_check(
            pack,
            gate_key_path=str(gate_key),
            gate_id="test-gate",
            output_dir=root / "out",
        )

    def test_current_evidence_commits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.run_case(root)
            self.assertEqual(
                (result.verdict, result.decision), ("VERIFIED", "COMMIT")
            )
            self.assertTrue((root / "out" / "decision.receipt.json").exists())

    def test_stale_review_denies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_case(Path(temporary), review_commit="old")
            self.assertEqual((result.verdict, result.decision), ("REJECTED", "DENY"))
            self.assertTrue(
                any("review-current" in reason for reason in result.reason_codes)
            )

    def test_missing_evidence_quarantines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_case(Path(temporary), include_review=False)
            self.assertEqual(
                (result.verdict, result.decision), ("UNDECIDABLE", "QUARANTINE")
            )
            self.assertTrue(
                any(
                    "artifact_missing:review" in reason
                    for reason in result.reason_codes
                )
            )

    def test_untrusted_producer_quarantines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_case(Path(temporary), trust_producer=False)
            self.assertEqual(
                (result.verdict, result.decision), ("UNDECIDABLE", "QUARANTINE")
            )

    def test_tampered_evidence_denies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_case(Path(temporary), tamper_tests_after_issue=True)
            self.assertEqual((result.verdict, result.decision), ("REJECTED", "DENY"))

    def test_ephemeral_disclosed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = self.make_case(root)
            result = run_check(pack, output_dir=root / "out", env={})
            self.assertEqual(result.gate_key_mode, "ephemeral")
            self.assertEqual(result.result["portable_authority"], "NONE")

    def test_path_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = self.make_case(root)
            value = json.loads(pack.read_text())
            value["policy"] = "../outside.json"
            pack.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "policy_path_escape"):
                run_check(pack)

    def test_github_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = self.make_case(root)
            summary = root / "summary.md"
            run_check(
                pack,
                output_dir=root / "out",
                env={"GITHUB_STEP_SUMMARY": str(summary)},
            )
            self.assertIn("OPENLINE CHECK", summary.read_text())


if __name__ == "__main__":
    unittest.main()
