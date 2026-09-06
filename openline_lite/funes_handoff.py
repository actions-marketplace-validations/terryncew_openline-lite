"""Bind Funes recall to a verified OpenLine model task without trusting memory.

Funes supplies verbatim cross-agent recall with provenance. OpenLine Lite keeps
that recall outside verified project state: it may guide a model, but anything
that should survive the handoff still needs receiver-checkable evidence.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Mapping

from .canonical import CanonicalJSONError, loads, object_hash, pretty, sha256_hex
from .model_handoff import build_model_task

RECALL_SCHEMA = "olp.funes_recall.v1"
RECALL_TRUST = "UNVERIFIED_MEMORY"
MAX_CONTROL_BYTES = 1_048_576
MAX_RECALL_BYTES = 131_072
MAX_VERSION_BYTES = 8_192
DEFAULT_TIMEOUT_SECONDS = 60


def _run(command: list[str], *, timeout: int, maximum: int) -> bytes:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ValueError("funes_not_found") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError("funes_timeout") from exc

    if len(completed.stdout) > maximum:
        raise ValueError("funes_output_too_large")
    if completed.returncode != 0:
        stderr = completed.stderr[:4_096].decode("utf-8", errors="replace").strip()
        suffix = f":{stderr}" if stderr else ""
        raise ValueError(f"funes_failed:{completed.returncode}{suffix}")
    try:
        completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("funes_output_not_utf8") from exc
    return completed.stdout


def capture_funes_recall(
    query: str,
    *,
    memory: str = "local",
    binary: str = "funes",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[dict[str, Any], bytes]:
    """Run Funes recall and return a hash-bound unverified-memory manifest."""

    if not isinstance(query, str) or not query or len(query.encode("utf-8")) > 16_384:
        raise ValueError("funes_query_invalid")
    if not isinstance(memory, str) or not memory or len(memory.encode("utf-8")) > 2_048:
        raise ValueError("funes_memory_invalid")
    if not isinstance(binary, str) or not binary:
        raise ValueError("funes_binary_invalid")

    version_bytes = _run(
        [binary, "--version"], timeout=timeout, maximum=MAX_VERSION_BYTES
    )
    version = version_bytes.decode("utf-8").strip()
    if not version:
        raise ValueError("funes_version_empty")

    command = [binary, "recall", query, "--memory", memory]
    recall = _run(command, timeout=timeout, maximum=MAX_RECALL_BYTES)
    manifest = {
        "schema": RECALL_SCHEMA,
        "source": "funes",
        "source_version": version,
        "query": query,
        "memory": memory,
        "content_sha256": sha256_hex(recall),
        "content_bytes": len(recall),
        "trust": RECALL_TRUST,
    }
    return manifest, recall


def recall_anchor(manifest: Mapping[str, Any]) -> str:
    _validate_recall_manifest(manifest)
    return (
        "[OPENLINE_UNVERIFIED_RECALL]\n"
        f"manifest_sha256={object_hash(manifest)}\n"
        f"content_sha256={manifest['content_sha256']}\n"
        "trust=UNVERIFIED_MEMORY\n"
        "rule=Recall may guide investigation, but it is not verified project state. "
        "Anything that should survive this handoff must still cite receiver-checkable "
        "evidence through the normal candidate schema."
    )


def build_funes_task(
    state: Mapping[str, Any],
    *,
    task_id: str,
    instructions: str,
    query: str,
    memory: str = "local",
    binary: str = "funes",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    manifest, recall = capture_funes_recall(
        query,
        memory=memory,
        binary=binary,
        timeout=timeout,
    )
    bound_instructions = instructions.rstrip() + "\n\n" + recall_anchor(manifest) + "\n"
    task = build_model_task(
        state,
        task_id=task_id,
        instructions=bound_instructions,
    )
    return task, manifest, recall


def _validate_recall_manifest(manifest: Mapping[str, Any]) -> None:
    expected = {
        "schema",
        "source",
        "source_version",
        "query",
        "memory",
        "content_sha256",
        "content_bytes",
        "trust",
    }
    if set(manifest) != expected or manifest.get("schema") != RECALL_SCHEMA:
        raise ValueError("funes_manifest_invalid")
    if manifest.get("source") != "funes" or manifest.get("trust") != RECALL_TRUST:
        raise ValueError("funes_manifest_invalid")
    if (
        not isinstance(manifest.get("source_version"), str)
        or not manifest["source_version"]
    ):
        raise ValueError("funes_manifest_invalid")
    if not isinstance(manifest.get("query"), str) or not manifest["query"]:
        raise ValueError("funes_manifest_invalid")
    if not isinstance(manifest.get("memory"), str) or not manifest["memory"]:
        raise ValueError("funes_manifest_invalid")
    content_hash = manifest.get("content_sha256")
    if not isinstance(content_hash, str) or len(content_hash) != 64:
        raise ValueError("funes_manifest_invalid")
    try:
        bytes.fromhex(content_hash)
    except ValueError as exc:
        raise ValueError("funes_manifest_invalid") from exc
    content_bytes = manifest.get("content_bytes")
    if (
        isinstance(content_bytes, bool)
        or not isinstance(content_bytes, int)
        or content_bytes < 0
    ):
        raise ValueError("funes_manifest_invalid")


def verify_funes_bundle(
    task: Mapping[str, Any], manifest: Mapping[str, Any], recall: bytes
) -> dict[str, Any]:
    """Verify recall integrity and that its manifest was bound into the task packet."""

    _validate_recall_manifest(manifest)
    if len(recall) > MAX_RECALL_BYTES:
        raise ValueError("funes_output_too_large")
    if len(recall) != manifest["content_bytes"]:
        raise ValueError("funes_recall_size_mismatch")
    if sha256_hex(recall) != manifest["content_sha256"]:
        raise ValueError("funes_recall_hash_mismatch")

    if not isinstance(task, Mapping) or set(task) != {
        "schema",
        "packet_sha256",
        "packet",
    }:
        raise ValueError("funes_task_invalid")
    packet = task.get("packet")
    if not isinstance(packet, Mapping):
        raise ValueError("funes_task_invalid")
    if object_hash(packet) != task.get("packet_sha256"):
        raise ValueError("funes_task_hash_mismatch")
    instructions = packet.get("instructions")
    if not isinstance(instructions, str):
        raise ValueError("funes_task_invalid")
    anchor = recall_anchor(manifest)
    if anchor not in instructions:
        raise ValueError("funes_manifest_not_bound_to_task")

    return {
        "schema": "olp.funes_bundle_check.v1",
        "status": "VERIFIED",
        "task_packet_sha256": task["packet_sha256"],
        "recall_manifest_sha256": object_hash(manifest),
        "recall_content_sha256": manifest["content_sha256"],
        "trust": RECALL_TRUST,
    }


def _read_bytes(path: Path, *, maximum: int = MAX_CONTROL_BYTES) -> bytes:
    if path.stat().st_size > maximum:
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


def _write_recall(path: Path, value: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    digest = sha256_hex(value)
    path.with_name(path.name + ".sha256").write_text(digest + "\n", encoding="ascii")
    return digest


def command_task(args: argparse.Namespace) -> int:
    state = _read_json(Path(args.state))
    instructions = _read_bytes(Path(args.instructions), maximum=65_536).decode("utf-8")
    task, manifest, recall = build_funes_task(
        state,
        task_id=args.task_id,
        instructions=instructions,
        query=args.query,
        memory=args.memory,
        binary=args.funes_bin,
        timeout=args.timeout,
    )

    out = Path(args.out_dir)
    recall_path = out / "recall.txt"
    manifest_path = out / "recall.json"
    task_path = out / "task.json"
    recall_sha256 = _write_recall(recall_path, recall)
    manifest_sha256 = _write_json(manifest_path, manifest)
    task_sha256 = _write_json(task_path, task)
    print(
        json.dumps(
            {
                "task": str(task_path),
                "task_envelope_sha256": task_sha256,
                "task_packet_sha256": task["packet_sha256"],
                "recall": str(recall_path),
                "recall_sha256": recall_sha256,
                "recall_manifest": str(manifest_path),
                "recall_manifest_sha256": manifest_sha256,
                "trust": RECALL_TRUST,
            },
            sort_keys=True,
        )
    )
    return 0


def command_verify_bundle(args: argparse.Namespace) -> int:
    task = _read_json(Path(args.task))
    manifest = _read_json(Path(args.recall_manifest))
    recall = _read_bytes(Path(args.recall), maximum=MAX_RECALL_BYTES)
    result = verify_funes_bundle(task, manifest, recall)
    print(json.dumps(result, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openline-funes-handoff",
        description=(
            "Bind Funes recall beneath OpenLine's verified model-handoff boundary."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    task_parser = sub.add_parser(
        "task",
        help="capture unverified Funes recall and bind its manifest to a verified task",
    )
    task_parser.add_argument("--state", required=True)
    task_parser.add_argument("--task-id", required=True)
    task_parser.add_argument("--instructions", required=True)
    task_parser.add_argument("--query", required=True)
    task_parser.add_argument("--memory", default="local")
    task_parser.add_argument("--funes-bin", default="funes")
    task_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    task_parser.add_argument("--out-dir", required=True)
    task_parser.set_defaults(func=command_task)

    verify_parser = sub.add_parser(
        "verify-bundle",
        help=(
            "verify recall bytes and prove the exact recall manifest "
            "is bound to the task"
        ),
    )
    verify_parser.add_argument("--task", required=True)
    verify_parser.add_argument("--recall-manifest", required=True)
    verify_parser.add_argument("--recall", required=True)
    verify_parser.set_defaults(func=command_verify_bundle)

    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        if getattr(args, "timeout", 1) <= 0:
            raise ValueError("funes_timeout_invalid")
        return int(args.func(args))
    except (OSError, UnicodeDecodeError, ValueError, CanonicalJSONError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
