"""CLI for receiver-verified model handoffs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .canonical import CanonicalJSONError, loads, object_hash, pretty
from .model_handoff import (
    build_model_task,
    initial_model_state,
    verify_model_candidate_bytes,
)

MAX_CONTROL_BYTES = 1_048_576


def _read_bytes(path: Path, *, maximum: int = MAX_CONTROL_BYTES) -> bytes:
    size = path.stat().st_size
    if size > maximum:
        raise ValueError(f"file_size_limit_exceeded:{path}")
    return path.read_bytes()


def _read_json(path: Path) -> dict[str, Any]:
    value = loads(_read_bytes(path))
    if not isinstance(value, dict):
        raise ValueError(f"object_required:{path}")
    return value


def _write_json(path: Path, value: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pretty(value), encoding="utf-8")
    digest = object_hash(value)
    path.with_name(path.name + ".sha256").write_text(digest + "\n", encoding="ascii")
    return digest


def command_init(args: argparse.Namespace) -> int:
    state = initial_model_state(args.project_id)
    digest = _write_json(Path(args.out), state)
    print(json.dumps({"state_sha256": digest, "state": args.out}))
    return 0


def command_task(args: argparse.Namespace) -> int:
    state = _read_json(Path(args.state))
    instructions = _read_bytes(Path(args.instructions), maximum=65_536).decode("utf-8")
    envelope = build_model_task(
        state,
        task_id=args.task_id,
        instructions=instructions,
    )
    digest = _write_json(Path(args.out), envelope)
    print(
        json.dumps(
            {
                "task_envelope_sha256": digest,
                "task_packet_sha256": envelope["packet_sha256"],
                "task": args.out,
            }
        )
    )
    return 0


def command_verify(args: argparse.Namespace) -> int:
    state = _read_json(Path(args.state))
    task = _read_json(Path(args.task))
    candidate = _read_bytes(Path(args.candidate), maximum=1_048_576)
    decision, next_state = verify_model_candidate_bytes(
        state,
        task,
        candidate,
        workspace=Path(args.workspace),
    )

    output = Path(args.out_dir)
    output.mkdir(parents=True, exist_ok=True)
    decision_path = output / "decision.json"
    decision_sha256 = _write_json(decision_path, decision)

    result: dict[str, Any] = {
        "verdict": decision["verdict"],
        "reason_codes": decision["reason_codes"],
        "decision": str(decision_path),
        "decision_sha256": decision_sha256,
    }
    if next_state is not None:
        state_path = output / "state.json"
        state_sha256 = _write_json(state_path, next_state)
        result["state"] = str(state_path)
        result["state_sha256"] = state_sha256

    print(json.dumps(result, sort_keys=True))
    return 0 if decision["verdict"] == "COMMIT" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openline-handoff",
        description=(
            "Receiver-owned wrapper for bounded model-to-model project handoffs."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init", help="create an empty verified project state")
    init_parser.add_argument("--project-id", required=True)
    init_parser.add_argument("--out", required=True)
    init_parser.set_defaults(func=command_init)

    task_parser = sub.add_parser(
        "task",
        help="bind one task to the exact verified state given to the model",
    )
    task_parser.add_argument("--state", required=True)
    task_parser.add_argument("--task-id", required=True)
    task_parser.add_argument("--instructions", required=True)
    task_parser.add_argument("--out", required=True)
    task_parser.set_defaults(func=command_task)

    verify_parser = sub.add_parser(
        "verify",
        help="verify a model candidate and emit the next state only on COMMIT",
    )
    verify_parser.add_argument("--state", required=True)
    verify_parser.add_argument("--task", required=True)
    verify_parser.add_argument("--candidate", required=True)
    verify_parser.add_argument("--workspace", required=True)
    verify_parser.add_argument("--out-dir", required=True)
    verify_parser.set_defaults(func=command_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return int(args.func(args))
    except (OSError, UnicodeDecodeError, ValueError, CanonicalJSONError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
