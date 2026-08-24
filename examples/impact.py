"""Show a three-decision trust boundary after one evidence invalidation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

from openline_lite import (
    EvidenceGateway,
    Policy,
    ReceiptGate,
    generate_private_key_hex,
    issue_source_receipt,
    public_key_hex,
)
from openline_lite.canonical import dumps, sha256_hex
from openline_lite.impact import (
    COMPLETE,
    INCOMPLETE,
    bind_verified_decision,
    build_impact_index,
    evaluate_impact,
)


BASE_TIME = datetime(2026, 8, 23, 18, 0, tzinfo=timezone.utc)


def make_bound_decision(
    *,
    label: str,
    required_evidence: str,
    completeness: str,
    producer_key: str,
    gate_key: str,
    evidence_bytes: dict[str, bytes],
):
    producer_id = "impact-demo-producer"
    gate_id = "impact-demo-gate"
    producer_trust = {producer_id: public_key_hex(producer_key)}
    gate_trust = {gate_id: public_key_hex(gate_key)}

    policy = Policy.from_mapping(
        {
            "policy_id": f"impact-demo-{label}",
            "version": "1",
            "allowed_actions": ["deploy"],
            "required_evidence": [required_evidence],
            "claim_rules": [
                {
                    "id": "required-evidence-is-current",
                    "evidence_id": required_evidence,
                    "pointer": "/ok",
                    "expected": True,
                }
            ],
            "max_age_seconds": 300,
            "on_undecidable": "QUARANTINE",
            "rollback_supported": False,
        }
    )

    payload = {
        "schema": "olp.source.v1",
        "issuer": producer_id,
        "issued_at": BASE_TIME.isoformat().replace("+00:00", "Z"),
        "run_id": f"impact-demo-{label}",
        "sequence": 0,
        "parent_hash": None,
        "action": {"type": "deploy", "name": "release", "target": label},
        "claim": f"{label} is acceptable under its receiver policy.",
        "evidence": [
            {"id": evidence_id, "sha256": sha256_hex(value)}
            for evidence_id, value in sorted(evidence_bytes.items())
        ],
    }
    source_receipt = issue_source_receipt(payload, producer_key, producer_id)
    source_bytes = dumps(source_receipt)

    intake = EvidenceGateway().inspect(
        source_bytes,
        source_format="olp.source.v1",
        trusted_keys=producer_trust,
    )
    decision = ReceiptGate(gate_id=gate_id, private_key=gate_key).decide(
        intake,
        artifacts=evidence_bytes,
        policy=policy,
        now=BASE_TIME + timedelta(seconds=10),
    )
    decision_bytes = dumps(decision.receipt)

    return bind_verified_decision(
        decision_receipt_bytes=decision_bytes,
        source_receipt_bytes=source_bytes,
        trusted_gate_keys=gate_trust,
        trusted_producer_keys=producer_trust,
        binding_completeness=completeness,
        label=label,
    )


def main() -> None:
    producer_key = generate_private_key_hex()
    gate_key = generate_private_key_hex()
    evidence_bytes = {
        "dependency-state": dumps({"ok": True, "component": "lib-x@1.2.3"}),
        "benchmark": dumps({"ok": True, "score": 91}),
        "docs": dumps({"ok": True, "pages": 4}),
    }

    decisions = [
        make_bound_decision(
            label="deploy-api",
            required_evidence="dependency-state",
            completeness=COMPLETE,
            producer_key=producer_key,
            gate_key=gate_key,
            evidence_bytes=evidence_bytes,
        ),
        make_bound_decision(
            label="publish-benchmark",
            required_evidence="benchmark",
            completeness=COMPLETE,
            producer_key=producer_key,
            gate_key=gate_key,
            evidence_bytes=evidence_bytes,
        ),
        make_bound_decision(
            label="publish-docs",
            required_evidence="docs",
            completeness=INCOMPLETE,
            producer_key=producer_key,
            gate_key=gate_key,
            evidence_bytes=evidence_bytes,
        ),
    ]

    index = build_impact_index(decisions)
    revoked = sha256_hex(evidence_bytes["dependency-state"])
    result = evaluate_impact(index, [revoked])
    labels = {decision.decision_id: decision.label for decision in decisions}

    output = {
        "invalidated_evidence_sha256": revoked,
        "REOPEN": [labels[decision_id] for decision_id in result.reopen],
        "RETAIN": [labels[decision_id] for decision_id in result.retain],
        "UNDETERMINED": [
            labels[decision_id] for decision_id in result.undetermined
        ],
        "runtime_permission": "NONE",
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
