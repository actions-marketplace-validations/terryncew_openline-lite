from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openline_lite.canonical import dumps, object_hash, sha256_hex
from openline_lite.model_handoff import (
    CANDIDATE_SCHEMA,
    build_model_task,
    initial_model_state,
    verify_model_candidate_bytes,
)


class ModelHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name)
        self.state = initial_model_state("demo-project")
        self.task = build_model_task(
            self.state,
            task_id="task-001",
            instructions="Make the small change and report receiver-checkable facts.",
        )
        self.changed = self.workspace / "src.txt"
        self.changed.write_text("new code\n", encoding="utf-8")
        self.receipt = self.workspace / "test-receipt.json"
        self.receipt.write_bytes(dumps({"exit_code": 0, "suite": "unit"}))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def candidate(self) -> dict:
        return {
            "schema": CANDIDATE_SCHEMA,
            "task_id": "task-001",
            "input_state_sha256": object_hash(self.state),
            "task_packet_sha256": self.task["packet_sha256"],
            "producer": "claude",
            "changes": [
                {
                    "path": "src.txt",
                    "status": "present",
                    "sha256": sha256_hex(self.changed.read_bytes()),
                }
            ],
            "facts": [
                {
                    "id": "tests_exit_zero",
                    "evidence_path": "test-receipt.json",
                    "evidence_sha256": sha256_hex(self.receipt.read_bytes()),
                    "pointer": "/exit_code",
                    "expected": 0,
                }
            ],
            "claims": [
                {
                    "id": "tests_passed",
                    "text": "The tests passed.",
                    "support_fact_ids": ["tests_exit_zero"],
                }
            ],
            "unresolved": [],
        }

    def verify(self, candidate: dict):
        return verify_model_candidate_bytes(
            self.state,
            self.task,
            dumps(candidate),
            workspace=self.workspace,
        )

    def test_commit_promotes_only_receiver_verified_facts_and_files(self) -> None:
        decision, next_state = self.verify(self.candidate())
        self.assertEqual(decision["verdict"], "COMMIT")
        self.assertIsNotNone(next_state)
        assert next_state is not None
        self.assertEqual(next_state["sequence"], 1)
        self.assertEqual(next_state["facts"][0]["id"], "tests_exit_zero")
        self.assertEqual(next_state["facts"][0]["value"], 0)
        self.assertEqual(next_state["files"][0]["path"], "src.txt")

        next_task = build_model_task(
            next_state,
            task_id="task-002",
            instructions="Continue.",
        )
        rendered = dumps(next_task).decode("utf-8")
        self.assertNotIn("The tests passed.", rendered)
        self.assertIn("tests_exit_zero", rendered)

    def test_evidence_hash_mismatch_quarantines_without_new_state(self) -> None:
        candidate = self.candidate()
        candidate["facts"][0]["evidence_sha256"] = "00" * 32
        decision, next_state = self.verify(candidate)
        self.assertEqual(decision["verdict"], "QUARANTINE")
        self.assertIsNone(next_state)
        self.assertIn(
            "evidence_hash_mismatch:tests_exit_zero",
            decision["reason_codes"],
        )

    def test_unverified_claim_support_quarantines(self) -> None:
        candidate = self.candidate()
        candidate["claims"][0]["support_fact_ids"] = ["missing_fact"]
        decision, next_state = self.verify(candidate)
        self.assertEqual(decision["verdict"], "QUARANTINE")
        self.assertIsNone(next_state)
        self.assertIn(
            "claim_unverified_support:tests_passed",
            decision["reason_codes"],
        )

    def test_unresolved_item_quarantines(self) -> None:
        candidate = self.candidate()
        candidate["unresolved"] = [
            {"id": "unknown-ci", "description": "CI result has not arrived."}
        ]
        decision, next_state = self.verify(candidate)
        self.assertEqual(decision["verdict"], "QUARANTINE")
        self.assertIsNone(next_state)
        self.assertIn("candidate_has_unresolved_items", decision["reason_codes"])

    def test_wrong_input_state_is_denied(self) -> None:
        candidate = self.candidate()
        candidate["input_state_sha256"] = "11" * 32
        decision, next_state = self.verify(candidate)
        self.assertEqual(decision["verdict"], "DENY")
        self.assertIsNone(next_state)
        self.assertIn("candidate_state_mismatch", decision["reason_codes"])

    def test_workspace_escape_is_denied(self) -> None:
        candidate = self.candidate()
        candidate["changes"][0] = {
            "path": "../outside.txt",
            "status": "present",
            "sha256": "22" * 32,
        }
        decision, next_state = self.verify(candidate)
        self.assertEqual(decision["verdict"], "DENY")
        self.assertIsNone(next_state)
        self.assertIn("change_path_escape:../outside.txt", decision["reason_codes"])

    def test_invalid_json_is_denied_and_hashed_as_raw_bytes(self) -> None:
        raw = b'{"schema":'
        decision, next_state = verify_model_candidate_bytes(
            self.state,
            self.task,
            raw,
            workspace=self.workspace,
        )
        self.assertEqual(decision["verdict"], "DENY")
        self.assertIsNone(next_state)
        self.assertEqual(decision["candidate_hash_mode"], "raw")
        self.assertEqual(decision["candidate_sha256"], sha256_hex(raw))


if __name__ == "__main__":
    unittest.main()
