"""Independent-ish output contract verifier for the canonical OTel -> Impact demo."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

EXPECTED_OTEL_COMMIT = "19bcef659e59704b71ed6f1ac910253a60f369ab"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    args = parser.parse_args()
    root = Path(args.output).resolve()
    summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))

    assert summary["schema"] == "openline.otel-impact-demo.v1"
    assert summary["openline_otel_commit"] == EXPECTED_OTEL_COMMIT
    assert summary["counts"] == {"REOPEN": 3, "RETAIN": 22, "UNDETERMINED": 2}
    assert summary["runtime_permission"] == "NONE"
    assert summary["policy_authority"] == "receiver_owned"
    assert len(summary["REOPEN"]) == 3
    assert len(summary["RETAIN"]) == 22
    assert len(summary["UNDETERMINED"]) == 2

    revoked = summary["invalidated_evidence"]
    receipt_path = root / "otel-receipts" / f"{revoked['id']}.json"
    assert hashlib.sha256(receipt_path.read_bytes()).hexdigest() == revoked["sha256"]

    for evidence_id, item in summary["otel_receipts"].items():
        assert item["signature_verified"] is True
        assert item["capture_loss"] is False
        receipt_bytes = (root / "otel-receipts" / f"{evidence_id}.json").read_bytes()
        assert hashlib.sha256(receipt_bytes).hexdigest() == item["sha256"]

    impact = json.loads(
        (root / ".openline-impact" / "impact.result.json").read_text(encoding="utf-8")
    )
    assert len(impact["reopen"]) == 3
    assert len(impact["retain"]) == 22
    assert len(impact["undetermined"]) == 2
    assert impact["runtime_permission"] == "NONE"

    print("OTEL_IMPACT_DEMO_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
