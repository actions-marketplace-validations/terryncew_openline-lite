"""Single authoritative conservation ledger for one mandate.

The conservation namespace is the mandate, never the actor identity. Internal
allocation moves/encumbers capacity; an external consequence converts live
capacity into committed history. Any operation that would violate the
invariant is refused before mutation, leaving observable state unchanged.
"""

from __future__ import annotations

from typing import Any

from .canonical import object_hash
from .policy_root import (
    PolicyArchive,
    PolicyBinding,
    PolicyRootError,
    make_binding,
)


REASON_AMOUNT_INVALID = "amount_invalid"
REASON_ACTOR_UNKNOWN = "actor_unknown"
REASON_INSUFFICIENT_AVAILABLE = "insufficient_available"


class LedgerRefused(Exception):
    """An operation was refused before mutation; ledger state is unchanged."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _require_actor_id(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise LedgerRefused("actor_id_invalid")
    return value


def _require_amount(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise LedgerRefused(REASON_AMOUNT_INVALID)
    return value


class MandateLedger:
    """One mandate, one authoritative ledger, one fixed capacity."""

    def __init__(self, *, binding: PolicyBinding, capacity: int) -> None:
        self._binding = binding
        self._capacity = capacity
        self._actors: dict[str, int] = {}
        self._committed = 0
        self._receipts: list[dict[str, Any]] = []

    @classmethod
    def begin(
        cls,
        archive: PolicyArchive,
        *,
        policy_id: str,
        policy_version: str,
        section_name: str = "spend",
    ) -> "MandateLedger":
        """Open the ledger bound to one archived policy version.

        The mandate capacity is read from the bound section's
        ``mandate_capacity`` field, so the policy content itself defines the
        conserved pool. The binding is derived from archived content, never
        from caller-supplied hashes.
        """
        try:
            content = archive.root_content(policy_id, policy_version)
        except PolicyRootError as exc:
            raise LedgerRefused("unknown_policy_version") from exc
        sections = content["sections"]
        if section_name not in sections:
            raise LedgerRefused("ledger_section_unknown")
        section = sections[section_name]
        capacity = section.get("mandate_capacity") if isinstance(section, dict) else None
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity <= 0:
            raise LedgerRefused("capacity_invalid")
        binding = make_binding(policy_id, policy_version, sections, section_name)
        return cls(binding=binding, capacity=capacity)

    @property
    def binding(self) -> PolicyBinding:
        return self._binding

    @property
    def capacity(self) -> int:
        return self._capacity

    def balances(self) -> dict[str, int]:
        return dict(self._actors)

    def committed(self) -> int:
        return self._committed

    def live_unspent(self) -> int:
        return sum(self._actors.values())

    def check_invariant(self) -> bool:
        """live unspent authority + externally committed == original capacity."""
        return self.live_unspent() + self._committed == self._capacity

    def state(self) -> dict[str, Any]:
        return {
            "capacity": self._capacity,
            "actors": self.balances(),
            "committed": self._committed,
            "live_unspent": self.live_unspent(),
            "binding": self._binding.to_dict(),
        }

    def receipts(self) -> list[dict[str, Any]]:
        return list(self._receipts)

    def admit_actor(self, actor_id: str) -> None:
        """Admit an actor inside the mandate boundary.

        Admission creates no capacity. The mandate's original capacity vests in
        the first admitted actor; later admissions (spawned, replaced, or
        renamed actors under the same mandate) start at zero. Re-admission is
        a no-op.
        """
        actor_id = _require_actor_id(actor_id)
        if actor_id in self._actors:
            return
        self._actors[actor_id] = self._capacity if not self._actors else 0
        assert self.check_invariant(), "conservation_invariant_violated"

    def allocate(self, from_id: str, to_id: str, amount: int) -> dict[str, Any]:
        """Move live capacity between two admitted actors (inside boundary)."""
        from_id = _require_actor_id(from_id)
        to_id = _require_actor_id(to_id)
        amount = _require_amount(amount)
        if from_id not in self._actors or to_id not in self._actors:
            raise LedgerRefused(REASON_ACTOR_UNKNOWN)
        if self._actors[from_id] < amount:
            raise LedgerRefused(REASON_INSUFFICIENT_AVAILABLE)
        self._actors[from_id] -= amount
        self._actors[to_id] += amount
        assert self.check_invariant(), "conservation_invariant_violated"
        return self._record(
            "internal_allocation", {"from": from_id, "to": to_id, "amount": amount}
        )

    def commit_external(self, actor_id: str, amount: int) -> dict[str, Any]:
        """Convert live capacity into committed consequence (crosses boundary)."""
        actor_id = _require_actor_id(actor_id)
        amount = _require_amount(amount)
        if actor_id not in self._actors:
            raise LedgerRefused(REASON_ACTOR_UNKNOWN)
        if self._actors[actor_id] < amount:
            raise LedgerRefused(REASON_INSUFFICIENT_AVAILABLE)
        self._actors[actor_id] -= amount
        self._committed += amount
        assert self.check_invariant(), "conservation_invariant_violated"
        return self._record(
            "external_consequence", {"actor": actor_id, "amount": amount}
        )

    def _record(self, event: str, detail: dict[str, Any]) -> dict[str, Any]:
        receipt: dict[str, Any] = {
            "event": event,
            "detail": detail,
            "actors": self.balances(),
            "committed": self._committed,
            "capacity": self._capacity,
            "binding": self._binding.to_dict(),
        }
        receipt["receipt_hash"] = object_hash(
            {key: value for key, value in receipt.items() if key != "receipt_hash"}
        )
        self._receipts.append(receipt)
        return receipt
