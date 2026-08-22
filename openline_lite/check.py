"""One-command receiver check over OpenLine Lite's existing evidence gate."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .canonical import loads, pretty, sha256_hex
from .continuity import ContinuityResult, analyze_continuity
from .crypto import generate_private_key_hex, public_key_hex
from .gate import DecisionResult, ReceiptGate
from .gateway import EvidenceGateway, NativeOLPAdapter
from .policy import Policy
from .wire import SOURCE_SCHEMA, verify_decision_receipt

CHECK_SCHEMA = "openline.check.v1"
MAX_CONTROL_BYTES = 1_048_576
MAX_ARTIFACT_BYTES = 8_388_608
MAX_TOTAL_ARTIFACT_BYTES = 33_554_432
MAX_EVIDENCE_FILES = 256


@dataclass(frozen=True)
class CheckRun:
    label: str
    verdict: str
    decision: str
    reason_codes: tuple[str, ...]
    decision_receipt: dict[str, Any]
    decision_receipt_sha256: str
    gate_public_key: str
    gate_key_mode: str
    proof_card: str
    result: dict[str, Any]


def _read_bytes(path: Path, maximum: int) -> bytes:
    size = path.stat().st_size
    if size > maximum:
        raise ValueError(f"file_size_limit_exceeded:{path.name}")
    return path.read_bytes()


def _read_object(path: Path) -> dict[str, Any]:
    value = loads(_read_bytes(path, MAX_CONTROL_BYTES))
    if not isinstance(value, dict):
        raise ValueError(f"object_required:{path.name}")
    return value


def _within(base: Path, relative: str, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label}_path_invalid")
    candidate = (base / relative).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"{label}_path_escape") from exc
    return candidate


def _parse_now(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("now_timezone_missing")
    return parsed.astimezone(timezone.utc)


def _validate_pack(pack: Mapping[str, Any]) -> dict[str, Any]:
    required = {"schema", "label", "source", "producer_trust", "policy", "evidence"}
    optional = {"source_format", "side_effect_observed", "now", "continuity"}
    unknown = set(pack) - required - optional
    missing = required - set(pack)
    if missing:
        raise ValueError("check_pack_missing:" + ",".join(sorted(missing)))
    if unknown:
        raise ValueError("check_pack_unknown:" + ",".join(sorted(unknown)))
    if pack["schema"] != CHECK_SCHEMA:
        raise ValueError("check_schema_unsupported")
    if not isinstance(pack["label"], str) or not pack["label"].strip():
        raise ValueError("check_label_invalid")
    if pack.get("source_format", SOURCE_SCHEMA) != SOURCE_SCHEMA:
        raise ValueError("check_source_format_unsupported")
    if not isinstance(pack["evidence"], dict):
        raise ValueError("check_evidence_invalid")
    if len(pack["evidence"]) > MAX_EVIDENCE_FILES:
        raise ValueError("check_evidence_count_limit_exceeded")
    if not all(
        isinstance(key, str) and key and isinstance(value, str) and value
        for key, value in pack["evidence"].items()
    ):
        raise ValueError("check_evidence_invalid")
    if not isinstance(pack.get("side_effect_observed", False), bool):
        raise ValueError("check_side_effect_invalid")
    if "continuity" in pack and not isinstance(pack["continuity"], Mapping):
        raise ValueError("check_continuity_invalid")
    return dict(pack)


def _load_artifacts(base: Path, evidence: Mapping[str, str]) -> dict[str, bytes]:
    artifacts: dict[str, bytes] = {}
    total = 0
    for evidence_id, relative in evidence.items():
        path = _within(base, relative, f"evidence:{evidence_id}")
        if not path.exists():
            continue
        data = _read_bytes(path, MAX_ARTIFACT_BYTES)
        total += len(data)
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            raise ValueError("check_evidence_total_size_limit_exceeded")
        artifacts[evidence_id] = data
    return artifacts


def _resolve_gate_key(
    gate_key_path: str | None,
    env: Mapping[str, str],
) -> tuple[str, str]:
    if gate_key_path:
        key = _read_bytes(Path(gate_key_path), 1024).decode("ascii").strip()
        return key, "pinned_file"
    env_key = env.get("OPENLINE_GATE_PRIVATE_KEY", "").strip()
    if env_key:
        return env_key, "pinned_env"
    return generate_private_key_hex(), "ephemeral"


def _remediation(reason_codes: tuple[str, ...]) -> list[str]:
    if not reason_codes:
        return ["No remediation required."]
    output: list[str] = []
    for reason in reason_codes:
        if "receipt_expired" in reason:
            item = "Refresh the source receipt and bind it to the current action."
        elif "source_key_untrusted" in reason:
            item = "Pin the producer public key in the receiver trust file."
        elif "source_key_mismatch" in reason:
            item = "Resolve the producer-key mismatch before relying on this source."
        elif "artifact_missing" in reason or "commitment_missing" in reason:
            item = "Provide every evidence artifact required by receiver policy."
        elif "artifact_hash_mismatch" in reason:
            item = "Reissue the source receipt against the exact evidence bytes being presented."
        elif "claim_fact_mismatch" in reason:
            rule_id = reason.rsplit(":", 1)[-1]
            item = f"Provide evidence satisfying receiver rule `{rule_id}`."
        elif "claim_fact_missing" in reason:
            rule_id = reason.rsplit(":", 1)[-1]
            item = f"Provide the fact required by receiver rule `{rule_id}`."
        elif "action_not_allowed" in reason:
            item = (
                "Use a receiver policy that explicitly admits this action, "
                "or do not perform it."
            )
        else:
            item = f"Resolve `{reason}` and run the check again."
        if item not in output:
            output.append(item)
    return output[:5]


def _render_card(
    *,
    label: str,
    source_payload: Mapping[str, Any],
    result: DecisionResult,
    gate_key_mode: str,
    receipt_hash: str,
    continuity: ContinuityResult | None,
) -> str:
    action = source_payload.get("action")
    action_text = label
    if isinstance(action, Mapping):
        name = action.get("name")
        target = action.get("target")
        if isinstance(name, str) and name:
            action_text = name + (
                f" -> {target}" if isinstance(target, str) and target else ""
            )
    lines = [
        "OPENLINE CHECK",
        "",
        f"Action: {action_text}",
        f"Evidence standing: {result.verdict}",
        f"Disposition: {result.decision}",
        "",
        "Why:",
    ]
    if result.reason_codes:
        lines.extend(f"- {reason}" for reason in result.reason_codes[:8])
    else:
        lines.append("- All receiver checks passed.")
    if continuity is not None:
        lines.extend(["", "Standing retained:"])
        if continuity.retained_claims:
            lines.extend(f"- {claim}" for claim in continuity.retained_claims[:8])
        else:
            lines.append("- None.")
        lines.extend(["", "Reverification required:"])
        if continuity.reopened_claims:
            for claim in continuity.reopened_claims[:8]:
                path = " -> ".join(continuity.paths.get(claim, (claim,)))
                marker = " [required]" if claim in continuity.reopened_required_claims else ""
                lines.append(f"- {claim}{marker}: {path}")
        else:
            lines.append("- None.")
        if continuity.blocked_evidence:
            lines.extend(["", "Evidence withheld pending reverification:"])
            lines.extend(f"- {item}" for item in continuity.blocked_evidence[:8])
    lines.extend(["", "What would clear it:"])
    lines.extend(f"- {item}" for item in _remediation(result.reason_codes))
    lines.extend(
        [
            "",
            f"Gate key: {gate_key_mode}",
            f"Decision receipt: sha256:{receipt_hash}",
        ]
    )
    if gate_key_mode == "ephemeral":
        lines.extend(
            [
                "",
                "Boundary: this run used an ephemeral gate key.",
                (
                    "The decision is integrity-checkable but has no externally "
                    "pinned gate authority."
                ),
            ]
        )
    return "\n".join(lines) + "\n"


def run_check(
    pack_path: Path,
    *,
    gate_key_path: str | None = None,
    gate_id: str = "openline-check",
    now: str | None = None,
    output_dir: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> CheckRun:
    pack_path = pack_path.resolve()
    base = pack_path.parent
    pack = _validate_pack(_read_object(pack_path))
    trust = _read_object(_within(base, pack["producer_trust"], "producer_trust"))
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in trust.items()):
        raise ValueError("producer_trust_invalid")
    policy = Policy.from_mapping(_read_object(_within(base, pack["policy"], "policy")))
    artifacts = _load_artifacts(base, pack["evidence"])
    continuity: ContinuityResult | None = None
    if "continuity" in pack:
        continuity = analyze_continuity(
            pack["continuity"],
            evidence_ids=frozenset(pack["evidence"]),
        )
        for evidence_id in continuity.blocked_evidence:
            artifacts.pop(evidence_id, None)
    source_path = _within(base, pack["source"], "source")
    source_bytes = _read_bytes(source_path, MAX_CONTROL_BYTES)

    intake = EvidenceGateway([NativeOLPAdapter()]).inspect(
        source_bytes,
        source_format=SOURCE_SCHEMA,
        trusted_keys=dict(trust),
    )

    effective_env = dict(os.environ if env is None else env)
    private_key, key_mode = _resolve_gate_key(gate_key_path, effective_env)
    gate_public = public_key_hex(private_key)
    effective_now = now if now is not None else pack.get("now")
    result = ReceiptGate(gate_id=gate_id, private_key=private_key).decide(
        intake,
        artifacts=artifacts,
        policy=policy,
        now=_parse_now(effective_now),
        side_effect_observed=bool(pack.get("side_effect_observed", False)),
    )
    receipt_bytes = pretty(result.receipt).encode("utf-8")
    receipt_hash = sha256_hex(receipt_bytes)
    verified = verify_decision_receipt(result.receipt, {gate_id: gate_public})
    if not verified["valid"]:
        raise ValueError("self_verification_failed:" + ",".join(verified["errors"]))

    card = _render_card(
        label=pack["label"],
        source_payload=intake.payload,
        result=result,
        gate_key_mode=key_mode,
        receipt_hash=receipt_hash,
        continuity=continuity,
    )
    public_result = {
        "schema": "openline.check-result.v1",
        "label": pack["label"],
        "verdict": result.verdict,
        "decision": result.decision,
        "reason_codes": list(result.reason_codes),
        "gate": {
            "id": gate_id,
            "key_mode": key_mode,
            "public_key": gate_public,
        },
        "source": {
            "format": intake.source_format,
            "sha256": intake.source_sha256,
            "integrity": intake.integrity.to_dict(),
            "provenance": intake.provenance.to_dict(),
            "normalization": intake.normalization.to_dict(),
        },
        "decision_receipt_sha256": receipt_hash,
        "decision_receipt_self_verified": True,
        "policy_authority": "receiver_owned",
        "portable_authority": "NONE",
        "selective_reverification": (
            None if continuity is None else continuity.to_dict()
        ),
    }
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "proof.md").write_text(card, encoding="utf-8")
        (output_dir / "result.json").write_text(pretty(public_result), encoding="utf-8")
        (output_dir / "decision.receipt.json").write_text(
            pretty(result.receipt), encoding="utf-8"
        )
    summary = effective_env.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as handle:
            handle.write("```\n" + card + "```\n")
    return CheckRun(
        label=pack["label"],
        verdict=result.verdict,
        decision=result.decision,
        reason_codes=result.reason_codes,
        decision_receipt=result.receipt,
        decision_receipt_sha256=receipt_hash,
        gate_public_key=gate_public,
        gate_key_mode=key_mode,
        proof_card=card,
        result=public_result,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openline-check",
        description="Ask whether the presented evidence earns the next action.",
    )
    parser.add_argument("pack", help="openline.check.v1 JSON file")
    parser.add_argument(
        "--gate-key", help="path to a 32-byte Ed25519 private key in hex"
    )
    parser.add_argument("--gate-id", default="openline-check")
    parser.add_argument("--now", help="ISO-8601 receiver evaluation time")
    parser.add_argument("--output-dir", default=".openline-check")
    parser.add_argument(
        "--json", action="store_true", help="print result JSON instead of card"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        run = run_check(
            Path(args.pack),
            gate_key_path=args.gate_key,
            gate_id=args.gate_id,
            now=args.now,
            output_dir=Path(args.output_dir),
        )
        if args.json:
            print(pretty(run.result), end="")
        else:
            print(run.proof_card, end="")
        return 0 if run.decision == "COMMIT" else 1
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
