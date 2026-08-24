"""Canonical OpenTelemetry -> OpenLine Impact bridge demo.

This demo deliberately keeps the trust boundaries separate:
- openline-otel captures ordinary OpenTelemetry spans and signs the resulting receipts;
- OpenLine Lite binds exact receipt bytes as receiver-required evidence at decision time;
- an externally supplied invalidation names one exact evidence hash;
- openline-impact partitions prior decisions into REOPEN / RETAIN / UNDETERMINED.

The demo does not discover the invalidation, infer missing dependencies, repair anything,
or grant runtime permission.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentelemetry.sdk.trace import TracerProvider

from openline_otel import OpenLineReceiptProcessor, ReceiptStore, verify_receipt
from openline_lite import (
    EvidenceGateway,
    Policy,
    ReceiptGate,
    generate_private_key_hex,
    issue_source_receipt,
    public_key_hex,
)
from openline_lite.canonical import dumps, pretty, sha256_hex
from openline_lite.impact_cli import run_impact_pack


OTEL_COMMIT = "19bcef659e59704b71ed6f1ac910253a60f369ab"
BASE_TIME = datetime(2026, 8, 24, 8, 0, tzinfo=timezone.utc)
PRODUCER_ID = "otel-impact-demo-producer"
GATE_ID = "otel-impact-demo-gate"


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def emit_trace_receipt(name: str, attributes: dict[str, str]) -> dict[str, object]:
    """Emit one real ordinary OTel span through openline-otel and return its signed receipt."""
    store = ReceiptStore()
    processor = OpenLineReceiptProcessor(
        Ed25519PrivateKey.generate(),
        grace_interval_seconds=0,
        receipt_store=store,
    )
    provider = TracerProvider()
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("openline-lite.otel-impact-demo", "1")

    with tracer.start_as_current_span(name, attributes=attributes):
        pass

    provider.shutdown()
    receipts = [item for item in store.all() if item.get("kind") == "trace_receipt"]
    if len(receipts) != 1:
        raise RuntimeError(f"expected_one_trace_receipt:{name}:{len(receipts)}")
    receipt = receipts[0]
    if not verify_receipt(receipt):
        raise RuntimeError(f"otel_receipt_signature_invalid:{name}")
    if receipt.get("capture_loss") is not False:
        raise RuntimeError(f"otel_capture_loss:{name}")
    return receipt


def issue_bound_decision(
    *,
    label: str,
    required_evidence: str,
    producer_key: str,
    gate_key: str,
    evidence_bytes: dict[str, bytes],
) -> tuple[bytes, bytes]:
    """Create one verified COMMIT whose frozen policy requires one exact OTel evidence item."""
    producer_trust = {PRODUCER_ID: public_key_hex(producer_key)}
    policy = Policy.from_mapping(
        {
            "policy_id": f"otel-impact-{label}",
            "version": "1",
            "allowed_actions": ["deploy"],
            "required_evidence": [required_evidence],
            "claim_rules": [
                {
                    "id": "otel-capture-has-no-observed-loss",
                    "evidence_id": required_evidence,
                    "pointer": "/capture_loss",
                    "expected": False,
                }
            ],
            "max_age_seconds": 300,
            "on_undecidable": "QUARANTINE",
            "rollback_supported": False,
        }
    )

    source_payload = {
        "schema": "olp.source.v1",
        "issuer": PRODUCER_ID,
        "issued_at": BASE_TIME.isoformat().replace("+00:00", "Z"),
        "run_id": f"otel-impact-{label}",
        "sequence": 0,
        "parent_hash": None,
        "action": {"type": "deploy", "name": "release", "target": label},
        "claim": f"{label} is acceptable under its receiver policy.",
        # Deliberately colocate all three observations. The policy binds only the one
        # required by this decision, so unrelated evidence must not expand impact.
        "evidence": [
            {"id": evidence_id, "sha256": sha256_hex(value)}
            for evidence_id, value in sorted(evidence_bytes.items())
        ],
    }
    source_receipt = issue_source_receipt(source_payload, producer_key, PRODUCER_ID)
    source_bytes = dumps(source_receipt)

    intake = EvidenceGateway().inspect(
        source_bytes,
        source_format="olp.source.v1",
        trusted_keys=producer_trust,
    )
    decision = ReceiptGate(gate_id=GATE_ID, private_key=gate_key).decide(
        intake,
        artifacts=evidence_bytes,
        policy=policy,
        now=BASE_TIME + timedelta(seconds=10),
    )
    if decision.decision != "COMMIT":
        raise RuntimeError(f"decision_did_not_commit:{label}:{decision.decision}")
    return source_bytes, dumps(decision.receipt)


def _labels(prefix: str, count: int) -> Iterable[str]:
    for index in range(1, count + 1):
        yield f"{prefix}-{index:02d}"


def build_demo(output_dir: Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    receipts_dir = output_dir / "otel-receipts"
    decisions_dir = output_dir / "decisions"
    receipts_dir.mkdir(exist_ok=True)
    decisions_dir.mkdir(exist_ok=True)

    otel_receipts = {
        "dependency-observation": emit_trace_receipt(
            "dependency.check",
            {"component": "lib-x", "version": "1.2.3", "result": "clean"},
        ),
        "build-observation": emit_trace_receipt(
            "build.verify",
            {"artifact": "api-image", "result": "passed"},
        ),
        "docs-observation": emit_trace_receipt(
            "docs.verify",
            {"site": "public-docs", "result": "passed"},
        ),
    }
    evidence_bytes = {
        evidence_id: _json_bytes(receipt)
        for evidence_id, receipt in otel_receipts.items()
    }
    for evidence_id, value in evidence_bytes.items():
        (receipts_dir / f"{evidence_id}.json").write_bytes(value)

    producer_key = generate_private_key_hex()
    gate_key = generate_private_key_hex()
    gate_trust = {GATE_ID: public_key_hex(gate_key)}
    producer_trust = {PRODUCER_ID: public_key_hex(producer_key)}
    (output_dir / "gate-trust.json").write_text(pretty(gate_trust), encoding="utf-8")
    (output_dir / "producer-trust.json").write_text(
        pretty(producer_trust), encoding="utf-8"
    )

    specs: list[tuple[str, str, str]] = []
    specs.extend(
        (label, "dependency-observation", "COMPLETE")
        for label in ("deploy-api", "publish-container", "approve-release")
    )
    specs.extend(
        (label, "build-observation", "COMPLETE")
        for label in _labels("retained-build", 11)
    )
    specs.extend(
        (label, "docs-observation", "COMPLETE")
        for label in _labels("retained-docs", 11)
    )
    specs.extend(
        (label, "build-observation", "INCOMPLETE")
        for label in ("unknown-service-a", "unknown-service-b")
    )

    pack_decisions: list[dict[str, str]] = []
    for label, required, completeness in specs:
        source_bytes, decision_bytes = issue_bound_decision(
            label=label,
            required_evidence=required,
            producer_key=producer_key,
            gate_key=gate_key,
            evidence_bytes=evidence_bytes,
        )
        safe = label.replace("/", "-")
        source_path = decisions_dir / f"{safe}.source.json"
        decision_path = decisions_dir / f"{safe}.decision.json"
        source_path.write_bytes(source_bytes)
        decision_path.write_bytes(decision_bytes)
        pack_decisions.append(
            {
                "decision_receipt": str(decision_path.relative_to(output_dir)),
                "source_receipt": str(source_path.relative_to(output_dir)),
                "binding_completeness": completeness,
                "label": label,
            }
        )

    revoked = sha256_hex(evidence_bytes["dependency-observation"])
    pack = {
        "schema": "openline.impact-pack.v1",
        "gate_trust": "gate-trust.json",
        "producer_trust": "producer-trust.json",
        "decisions": pack_decisions,
        "invalidated_evidence_sha256": [revoked],
    }
    pack_path = output_dir / "impact-pack.json"
    pack_path.write_text(pretty(pack), encoding="utf-8")

    public = run_impact_pack(pack_path, output_dir / ".openline-impact")
    index = public["index"]
    result = public["result"]
    by_id = {item["decision_id"]: item.get("label") for item in index["decisions"]}

    summary = {
        "schema": "openline.otel-impact-demo.v1",
        "openline_otel_commit": OTEL_COMMIT,
        "otel_receipts": {
            evidence_id: {
                "kind": receipt["kind"],
                "signature_verified": True,
                "capture_status": receipt["capture_status"],
                "capture_loss": receipt["capture_loss"],
                "sha256": sha256_hex(evidence_bytes[evidence_id]),
            }
            for evidence_id, receipt in sorted(otel_receipts.items())
        },
        "invalidated_evidence": {
            "id": "dependency-observation",
            "sha256": revoked,
        },
        "REOPEN": [by_id[item] for item in result["reopen"]],
        "RETAIN": [by_id[item] for item in result["retain"]],
        "UNDETERMINED": [by_id[item] for item in result["undetermined"]],
        "counts": {
            "REOPEN": len(result["reopen"]),
            "RETAIN": len(result["retain"]),
            "UNDETERMINED": len(result["undetermined"]),
        },
        "impact_index_sha256": result["index_sha256"],
        "impact_result_sha256": result["result_sha256"],
        "policy_authority": "receiver_owned",
        "runtime_permission": "NONE",
        "claim_boundary": (
            "The revocation is supplied externally. OTel capture remains self-attested/provisional. "
            "The demo localizes standing loss; it does not discover the break, repair state, or authorize execution."
        ),
    }
    (output_dir / "summary.json").write_text(pretty(summary), encoding="utf-8")
    return summary


def _print_card(summary: dict[str, object]) -> None:
    counts = summary["counts"]
    invalidated = summary["invalidated_evidence"]
    print("OPENLINE: OTel -> IMPACT")
    print()
    print(f"Evidence revoked: {invalidated['id']}")
    print(f"sha256:{invalidated['sha256']}")
    print()
    print("Affected standing:")
    print(f"REOPEN         {counts['REOPEN']}")
    print(f"RETAIN        {counts['RETAIN']}")
    print(f"UNDETERMINED   {counts['UNDETERMINED']}")
    print()
    print("Only decisions bound to the revoked evidence reopen.")
    print("No remediation executed. Runtime permission: NONE")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=".openline-otel-impact")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    summary = build_demo(Path(args.output).resolve())
    if args.json:
        print(pretty(summary), end="")
    else:
        _print_card(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
