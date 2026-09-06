from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openline_lite.canonical import dumps, object_hash, sha256_hex
from openline_lite.funes_handoff import (
    RECALL_TRUST,
    build_funes_task,
    capture_funes_recall,
    verify_funes_bundle,
)
from openline_lite.model_handoff import (
    CANDIDATE_SCHEMA,
    initial_model_state,
    verify_model_candidate_bytes,
)


class FunesHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.fake = self.root / "funes"
        self.fake.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "if sys.argv[1:] == ['--version']:\n"
            "    print('funes 1.3.0-test')\n"
            "    raise SystemExit(0)\n"
            "if len(sys.argv) >= 3 and sys.argv[1] == 'recall':\n"
            "    q = sys.argv[2]\n"
            "    print('[2026-01-01] claude /repo/abc123 text  score=0.999')\n"
            "    print('prior memory for: ' + q)\n"
            "    raise SystemExit(0)\n"
            "print('bad invocation', file=sys.stderr)\n"
            "raise SystemExit(7)\n",
            encoding="utf-8",
        )
        self.fake.chmod(self.fake.stat().st_mode | 0o111)
        self.state = initial_model_state("demo-project")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def task(self, query: str = "why did we choose this"):
        return build_funes_task(
            self.state,
            task_id="task-001",
            instructions="Inspect the current project and make the bounded change.",
            query=query,
            binary=str(self.fake),
        )

    def test_recall_is_hash_bound_to_task_but_not_verified_context(self) -> None:
        task, manifest, recall = self.task()
        result = verify_funes_bundle(task, manifest, recall)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["trust"], RECALL_TRUST)
        self.assertEqual(manifest["source_version"], "funes 1.3.0-test")
        self.assertEqual(manifest["content_sha256"], sha256_hex(recall))
        self.assertEqual(task["packet"]["verified_context"], {"facts": [], "files": []})
        self.assertNotIn(recall.decode("utf-8"), dumps(self.state).decode("utf-8"))
        self.assertIn(object_hash(manifest), task["packet"]["instructions"])

    def test_tampered_recall_is_rejected(self) -> None:
        task, manifest, recall = self.task()
        with self.assertRaisesRegex(ValueError, "funes_recall_hash_mismatch"):
            verify_funes_bundle(task, manifest, recall[:-1] + b"X")

    def test_different_manifest_is_not_bound_to_task(self) -> None:
        task, manifest, recall = self.task()
        changed = dict(manifest)
        changed["query"] = "different query"
        with self.assertRaisesRegex(ValueError, "funes_manifest_not_bound_to_task"):
            verify_funes_bundle(task, changed, recall)

    def test_memory_only_claim_cannot_become_verified_state(self) -> None:
        task, _manifest, _recall = self.task("tests passed before")
        candidate = {
            "schema": CANDIDATE_SCHEMA,
            "task_id": "task-001",
            "input_state_sha256": object_hash(self.state),
            "task_packet_sha256": task["packet_sha256"],
            "producer": "claude",
            "changes": [],
            "facts": [],
            "claims": [
                {
                    "id": "tests_passed",
                    "text": "The tests passed.",
                    "support_fact_ids": ["remembered_test_result"],
                }
            ],
            "unresolved": [],
        }
        decision, next_state = verify_model_candidate_bytes(
            self.state,
            task,
            dumps(candidate),
            workspace=self.workspace,
        )
        self.assertEqual(decision["verdict"], "QUARANTINE")
        self.assertIsNone(next_state)
        self.assertIn("claim_unverified_support:tests_passed", decision["reason_codes"])

    def test_verified_fact_survives_model_switch_recall_does_not(self) -> None:
        task, _manifest, recall = self.task("old rationale")
        receipt = self.workspace / "test-receipt.json"
        receipt.write_bytes(dumps({"exit_code": 0}))
        candidate = {
            "schema": CANDIDATE_SCHEMA,
            "task_id": "task-001",
            "input_state_sha256": object_hash(self.state),
            "task_packet_sha256": task["packet_sha256"],
            "producer": "claude",
            "changes": [],
            "facts": [
                {
                    "id": "tests_exit_zero",
                    "evidence_path": "test-receipt.json",
                    "evidence_sha256": sha256_hex(receipt.read_bytes()),
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
        decision, next_state = verify_model_candidate_bytes(
            self.state,
            task,
            dumps(candidate),
            workspace=self.workspace,
        )
        self.assertEqual(decision["verdict"], "COMMIT")
        assert next_state is not None

        next_task, _next_manifest, next_recall = build_funes_task(
            next_state,
            task_id="task-002",
            instructions="Continue with Codex.",
            query="what did Claude do",
            binary=str(self.fake),
        )
        self.assertEqual(
            next_task["packet"]["verified_context"]["facts"][0]["id"],
            "tests_exit_zero",
        )
        self.assertNotIn(recall.decode("utf-8"), dumps(next_state).decode("utf-8"))
        self.assertIn("what did Claude do", next_recall.decode("utf-8"))
        self.assertNotIn("old rationale", next_recall.decode("utf-8"))

    def test_funes_failure_is_closed(self) -> None:
        bad = self.root / "bad-funes"
        bad.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "if sys.argv[1:] == ['--version']:\n"
            "    print('funes bad')\n"
            "    raise SystemExit(0)\n"
            "print('index unavailable', file=sys.stderr)\n"
            "raise SystemExit(9)\n",
            encoding="utf-8",
        )
        bad.chmod(bad.stat().st_mode | 0o111)
        with self.assertRaisesRegex(ValueError, "funes_failed:9"):
            capture_funes_recall("anything", binary=str(bad))

    def test_missing_funes_is_closed(self) -> None:
        missing = self.root / "does-not-exist"
        with self.assertRaisesRegex(ValueError, "funes_not_found"):
            capture_funes_recall("anything", binary=str(missing))


if __name__ == "__main__":
    unittest.main()
