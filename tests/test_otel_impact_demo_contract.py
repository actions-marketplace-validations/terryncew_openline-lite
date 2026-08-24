"""Dependency-free guardrails for the optional OTel -> Impact example."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "otel-impact" / "demo.py"
REQ = ROOT / "examples" / "otel-impact" / "requirements.txt"


class OTelImpactDemoContractTests(unittest.TestCase):
    def test_demo_keeps_runtime_permission_none(self):
        text = DEMO.read_text(encoding="utf-8")
        self.assertIn('"runtime_permission": "NONE"', text)
        self.assertIn("run_impact_pack", text)

    def test_demo_has_expected_partition_fixture(self):
        text = DEMO.read_text(encoding="utf-8")
        self.assertIn('"deploy-api", "publish-container", "approve-release"', text)
        self.assertIn('_labels("retained-build", 11)', text)
        self.assertIn('_labels("retained-docs", 11)', text)
        self.assertIn('"unknown-service-a", "unknown-service-b"', text)

    def test_openline_otel_is_exactly_pinned(self):
        requirement = REQ.read_text(encoding="utf-8").strip()
        self.assertEqual(
            requirement,
            "openline-otel @ git+https://github.com/terryncew/openline-otel.git@19bcef659e59704b71ed6f1ac910253a60f369ab",
        )


if __name__ == "__main__":
    unittest.main()
