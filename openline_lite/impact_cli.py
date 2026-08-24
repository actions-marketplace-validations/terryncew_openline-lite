"""CLI for the OpenLine decision trust-boundary index."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from .canonical import loads, pretty
from .impact import bind_verified_decision, build_impact_index, evaluate_impact

PACK_SCHEMA = "openline.impact-pack.v1"
MAX_PACK_BYTES = 1_048_576
MAX_RECEIPT_BYTES = 1_048_576


def _read(path: Path, maximum: int) -> bytes:
    if path.stat().st_size > maximum:
        raise ValueError(f"file_size_limit_exceeded:{path.name}")
    return path.read_bytes()


def _object(path: Path) -> dict[str, Any]:
    value = loads(_read(path, MAX_PACK_BYTES))
    if not isinstance(value, dict):
        raise ValueError(f"object_required:{path.name}")
    return value


def _within(base: Path, relative: object, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label}_path_invalid")
    candidate = (base / relative).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"{label}_path_escape") from exc
    return candidate


def _trust(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label}_invalid")
    if not all(
        isinstance(key, str) and key and isinstance(public, str) and public
        for key, public in value.items()
    ):
        raise ValueError(f"{label}_invalid")
    return dict(value)


def run_impact_pack(pack_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    pack_path = pack_path.resolve()
    base = pack_path.parent
    pack = _object(pack_path)
    required = {
        "schema",
        "gate_trust",
        "producer_trust",
        "decisions",
        "invalidated_evidence_sha256",
    }
    if set(pack) != required:
        missing = required - set(pack)
        unknown = set(pack) - required
        if missing:
            raise ValueError("impact_pack_missing:" + ",".join(sorted(missing)))
        raise ValueError("impact_pack_unknown:" + ",".join(sorted(unknown)))
    if pack["schema"] != PACK_SCHEMA:
        raise ValueError("impact_pack_schema_unsupported")

    gate_trust = _trust(
        _object(_within(base, pack["gate_trust"], "gate_trust")),
        "gate_trust",
    )
    producer_trust = _trust(
        _object(_within(base, pack["producer_trust"], "producer_trust")),
        "producer_trust",
    )

    raw_decisions = pack["decisions"]
    if not isinstance(raw_decisions, list) or not raw_decisions:
        raise ValueError("impact_pack_decisions_invalid")

    bound = []
    for index, item in enumerate(raw_decisions):
        if not isinstance(item, Mapping):
            raise ValueError(f"impact_pack_decision_invalid:{index}")
        allowed = {"decision_receipt", "source_receipt", "binding_completeness", "label"}
        if set(item) - allowed or not {"decision_receipt", "source_receipt", "binding_completeness"} <= set(item):
            raise ValueError(f"impact_pack_decision_fields_invalid:{index}")
        decision_path = _within(base, item["decision_receipt"], f"decision:{index}")
        source_path = _within(base, item["source_receipt"], f"source:{index}")
        bound.append(
            bind_verified_decision(
                decision_receipt_bytes=_read(decision_path, MAX_RECEIPT_BYTES),
                source_receipt_bytes=_read(source_path, MAX_RECEIPT_BYTES),
                trusted_gate_keys=gate_trust,
                trusted_producer_keys=producer_trust,
                binding_completeness=str(item["binding_completeness"]),
                label=item.get("label"),
            )
        )

    invalidated = pack["invalidated_evidence_sha256"]
    if not isinstance(invalidated, list):
        raise ValueError("impact_pack_invalidations_invalid")
    index_obj = build_impact_index(bound)
    result = evaluate_impact(index_obj, invalidated)
    public = {
        "schema": "openline.impact-pack-result.v1",
        "index": index_obj.to_dict(),
        "result": result.to_dict(),
    }
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "impact.index.json").write_text(pretty(index_obj.to_dict()), encoding="utf-8")
        (output_dir / "impact.result.json").write_text(pretty(result.to_dict()), encoding="utf-8")
    return public


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openline-impact",
        description="Find the exact boundary of lost trust after evidence invalidation.",
    )
    parser.add_argument("pack", help="openline.impact-pack.v1 JSON file")
    parser.add_argument("--output-dir", default=".openline-impact")
    parser.add_argument("--json", action="store_true")
    return parser


def _card(public: Mapping[str, Any]) -> str:
    result = public["result"]
    lines = [
        "OPENLINE IMPACT",
        "",
        f"REOPEN: {len(result['reopen'])}",
        f"RETAIN: {len(result['retain'])}",
        f"UNDETERMINED: {len(result['undetermined'])}",
        "",
        f"Index: sha256:{result['index_sha256']}",
        f"Result: sha256:{result['result_sha256']}",
        "",
        "Boundary: this tool localizes standing loss. It does not authorize execution.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        public = run_impact_pack(Path(args.pack), Path(args.output_dir))
        print(pretty(public) if args.json else _card(public), end="")
        return 0
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
