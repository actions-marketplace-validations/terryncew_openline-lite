"""Versioned, content-addressed owner-policy roots with section bindings.

A small common primitive: heterogeneous records can cryptographically name the
exact version of the owner policy that governed them, and the exact policy
section the producing component enforced.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import dumps, loads, object_hash, validate


BINDING_FIELDS = (
    "policy_id",
    "policy_version",
    "root_hash",
    "section_name",
    "section_hash",
)

REASON_BINDING_VALID = "binding_valid"
REASON_UNKNOWN_POLICY_VERSION = "unknown_policy_version"
REASON_POLICY_ID_MISMATCH = "policy_id_mismatch"
REASON_ROOT_HASH_MISMATCH = "root_hash_mismatch"
REASON_SECTION_UNKNOWN = "section_unknown"
REASON_SECTION_HASH_MISMATCH = "section_hash_mismatch"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PolicyRootError(ValueError):
    """The policy root, binding, or archive operation is invalid."""


def _require_id(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyRootError(f"{field}_invalid")
    return value


def _require_hash(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.match(value) is None:
        raise PolicyRootError(f"{field}_invalid")
    return value


def canonical_root_content(
    policy_id: str, policy_version: str, sections: Mapping[str, Any]
) -> dict[str, Any]:
    """Build the exact canonical content that root_hash is computed over."""
    _require_id(policy_id, field="policy_id")
    _require_id(policy_version, field="policy_version")
    if not isinstance(sections, Mapping) or not sections:
        raise PolicyRootError("policy_sections_invalid")
    clean: dict[str, Any] = {}
    for name, content in sections.items():
        _require_id(name, field="section_name")
        validate(content, path="$.sections")
        clean[name] = content
    return {
        "policy_id": policy_id,
        "policy_version": policy_version,
        "sections": clean,
    }


def root_hash_for(
    policy_id: str, policy_version: str, sections: Mapping[str, Any]
) -> str:
    """SHA-256 over the canonical root content (never over a stored hash)."""
    return object_hash(canonical_root_content(policy_id, policy_version, sections))


def section_hash_for(section_content: Any) -> str:
    """SHA-256 over the exact canonical content of one named section."""
    validate(section_content, path="$.section")
    return object_hash(section_content)


@dataclass(frozen=True)
class PolicyBinding:
    """A record's claim about which policy version and section governed it."""

    policy_id: str
    policy_version: str
    root_hash: str
    section_name: str
    section_hash: str

    @classmethod
    def from_mapping(cls, value: Any) -> "PolicyBinding":
        if not isinstance(value, Mapping) or set(value) != set(BINDING_FIELDS):
            raise PolicyRootError("binding_fields_invalid")
        return cls(
            policy_id=_require_id(value["policy_id"], field="policy_id"),
            policy_version=_require_id(value["policy_version"], field="policy_version"),
            root_hash=_require_hash(value["root_hash"], field="root_hash"),
            section_name=_require_id(value["section_name"], field="section_name"),
            section_hash=_require_hash(value["section_hash"], field="section_hash"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in BINDING_FIELDS}


def make_binding(
    policy_id: str,
    policy_version: str,
    sections: Mapping[str, Any],
    section_name: str,
) -> PolicyBinding:
    """Create a binding for one section of an exact policy version."""
    content = canonical_root_content(policy_id, policy_version, sections)
    if section_name not in content["sections"]:
        raise PolicyRootError("binding_section_unknown")
    return PolicyBinding(
        policy_id=content["policy_id"],
        policy_version=content["policy_version"],
        root_hash=object_hash(content),
        section_name=section_name,
        section_hash=object_hash(content["sections"][section_name]),
    )


class PolicyArchive:
    """Immutable admission of exact policy versions.

    Within one policy_id, one policy_version resolves to exactly one
    root_hash. Re-admission of identical content is idempotent; reusing a
    version label with different content is rejected.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], dict[str, Any]] = {}

    def admit(
        self, policy_id: str, policy_version: str, sections: Mapping[str, Any]
    ) -> str:
        content = canonical_root_content(policy_id, policy_version, sections)
        root_hash = object_hash(content)
        key = (content["policy_id"], content["policy_version"])
        existing = self._entries.get(key)
        if existing is not None:
            if existing["root_hash"] != root_hash:
                raise PolicyRootError("policy_version_reuse_with_different_root")
            return root_hash
        # Deep-copy through canonical JSON so later caller mutation cannot
        # alter the archived version.
        self._entries[key] = {"root_hash": root_hash, "content": loads(dumps(content))}
        return root_hash

    def root_content(self, policy_id: str, policy_version: str) -> dict[str, Any]:
        """Return the exact archived canonical content for one version."""
        try:
            return self._entries[(policy_id, policy_version)]["content"]
        except KeyError:
            raise PolicyRootError(REASON_UNKNOWN_POLICY_VERSION) from None

    def versions(self, policy_id: str) -> tuple[str, ...]:
        return tuple(version for (pid, version) in self._entries if pid == policy_id)


def verify_binding(
    binding: PolicyBinding, archive: PolicyArchive
) -> tuple[bool, str]:
    """Pure verification of a binding against the archive.

    Never falls back to the newest version: the claimed version must resolve
    in the archive, and every field must recompute exactly.
    """
    if not isinstance(binding, PolicyBinding):
        raise PolicyRootError("binding_invalid")
    try:
        content = archive.root_content(binding.policy_id, binding.policy_version)
    except PolicyRootError:
        return (False, REASON_UNKNOWN_POLICY_VERSION)
    if content["policy_id"] != binding.policy_id:
        return (False, REASON_POLICY_ID_MISMATCH)
    if object_hash(content) != binding.root_hash:
        return (False, REASON_ROOT_HASH_MISMATCH)
    sections = content["sections"]
    if binding.section_name not in sections:
        return (False, REASON_SECTION_UNKNOWN)
    if object_hash(sections[binding.section_name]) != binding.section_hash:
        return (False, REASON_SECTION_HASH_MISMATCH)
    return (True, REASON_BINDING_VALID)
