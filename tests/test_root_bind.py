"""Adversarial tests for ROOT-BIND-001.

SEALED fixture: encodes the frozen preregistration events for the versioned
owner-policy root primitive and the single-ledger mandate conservation
fixture. Do not invoke before scientific-contact approval.
"""

from __future__ import annotations

import unittest

from openline_lite import policy_root as pr
from openline_lite.canonical import object_hash
from openline_lite.mandate_ledger import LedgerRefused, MandateLedger


POLICY_ID = "owner-policy-test"


def sections_v1():
    return {
        "acceptance": {"protected_paths": ["src/"], "required_checks": ["tests"]},
        "authority": {"owner": "owner-1", "admission": "explicit"},
        "spend": {"mandate_capacity": 100, "unit": "abstract"},
        "consequence": {"external_final": True},
    }


def sections_v2():
    changed = sections_v1()
    changed["acceptance"] = {
        "protected_paths": ["src/"],
        "required_checks": ["tests", "lint"],
    }
    return changed


def archive_with_v1():
    archive = pr.PolicyArchive()
    root = archive.admit(POLICY_ID, "v1", sections_v1())
    return archive, root


class PolicyRootBindingTests(unittest.TestCase):
    def test_root_hash_is_content_addressed(self):
        archive, root = archive_with_v1()
        self.assertEqual(root, pr.root_hash_for(POLICY_ID, "v1", sections_v1()))
        # Re-admission of identical content is idempotent.
        self.assertEqual(root, archive.admit(POLICY_ID, "v1", sections_v1()))

    def test_changed_content_changes_root(self):
        archive, root_v1 = archive_with_v1()
        root_v2 = archive.admit(POLICY_ID, "v2", sections_v2())
        self.assertNotEqual(root_v1, root_v2)

    def test_version_reuse_with_different_root_rejected(self):
        archive, _ = archive_with_v1()
        with self.assertRaises(pr.PolicyRootError):
            archive.admit(POLICY_ID, "v1", sections_v2())

    def test_section_hash_recomputes_from_section_content(self):
        self.assertEqual(
            pr.section_hash_for(sections_v1()["spend"]),
            pr.section_hash_for({"mandate_capacity": 100, "unit": "abstract"}),
        )

    def test_binding_verifies(self):
        archive, root = archive_with_v1()
        binding = pr.make_binding(POLICY_ID, "v1", sections_v1(), "spend")
        self.assertEqual(binding.root_hash, root)
        self.assertEqual(
            pr.verify_binding(binding, archive), (True, pr.REASON_BINDING_VALID)
        )

    def test_unknown_version_fails(self):
        archive, _ = archive_with_v1()
        binding = pr.make_binding(POLICY_ID, "v1", sections_v1(), "spend")
        forged = pr.PolicyBinding(
            policy_id=binding.policy_id,
            policy_version="v99",
            root_hash=binding.root_hash,
            section_name=binding.section_name,
            section_hash=binding.section_hash,
        )
        self.assertEqual(
            pr.verify_binding(forged, archive),
            (False, pr.REASON_UNKNOWN_POLICY_VERSION),
        )

    def test_wrong_root_fails(self):
        archive, _ = archive_with_v1()
        binding = pr.make_binding(POLICY_ID, "v1", sections_v1(), "spend")
        forged = pr.PolicyBinding(
            policy_id=binding.policy_id,
            policy_version=binding.policy_version,
            root_hash="0" * 64,
            section_name=binding.section_name,
            section_hash=binding.section_hash,
        )
        self.assertEqual(
            pr.verify_binding(forged, archive), (False, pr.REASON_ROOT_HASH_MISMATCH)
        )

    def test_unknown_section_fails(self):
        archive, _ = archive_with_v1()
        binding = pr.make_binding(POLICY_ID, "v1", sections_v1(), "spend")
        forged = pr.PolicyBinding(
            policy_id=binding.policy_id,
            policy_version=binding.policy_version,
            root_hash=binding.root_hash,
            section_name="nope",
            section_hash=binding.section_hash,
        )
        self.assertEqual(
            pr.verify_binding(forged, archive), (False, pr.REASON_SECTION_UNKNOWN)
        )

    def test_wrong_section_hash_fails(self):
        archive, _ = archive_with_v1()
        binding = pr.make_binding(POLICY_ID, "v1", sections_v1(), "spend")
        forged = pr.PolicyBinding(
            policy_id=binding.policy_id,
            policy_version=binding.policy_version,
            root_hash=binding.root_hash,
            section_name=binding.section_name,
            section_hash="f" * 64,
        )
        self.assertEqual(
            pr.verify_binding(forged, archive),
            (False, pr.REASON_SECTION_HASH_MISMATCH),
        )

    def test_section_name_is_part_of_binding(self):
        sections = {"a": {"x": 1}, "b": {"x": 1}}
        archive = pr.PolicyArchive()
        archive.admit("p", "v1", sections)
        binding_a = pr.make_binding("p", "v1", sections, "a")
        binding_b = pr.make_binding("p", "v1", sections, "b")
        # Identical content may share a hash, but the name still travels.
        self.assertEqual(binding_a.section_hash, binding_b.section_hash)
        self.assertEqual(binding_a.section_name, "a")
        self.assertEqual(binding_b.section_name, "b")
        self.assertEqual(
            pr.verify_binding(binding_a, archive), (True, pr.REASON_BINDING_VALID)
        )

    def test_v1_receipts_survive_v2_and_relabel_fails(self):
        archive, root_v1 = archive_with_v1()
        binding_v1 = pr.make_binding(POLICY_ID, "v1", sections_v1(), "spend")
        root_v2 = archive.admit(POLICY_ID, "v2", sections_v2())
        self.assertNotEqual(root_v1, root_v2)
        # Historical v1 binding still verifies against archived v1.
        self.assertEqual(
            pr.verify_binding(binding_v1, archive), (True, pr.REASON_BINDING_VALID)
        )
        # A v1 binding relabeled as v2 must fail.
        relabeled = pr.PolicyBinding(
            policy_id=binding_v1.policy_id,
            policy_version="v2",
            root_hash=binding_v1.root_hash,
            section_name=binding_v1.section_name,
            section_hash=binding_v1.section_hash,
        )
        self.assertEqual(
            pr.verify_binding(relabeled, archive), (False, pr.REASON_ROOT_HASH_MISMATCH)
        )

    def test_tampered_content_binding_fails(self):
        archive, _ = archive_with_v1()
        tampered = sections_v1()
        tampered["spend"] = {"mandate_capacity": 1000, "unit": "abstract"}
        forged = pr.make_binding(POLICY_ID, "v1", tampered, "spend")
        ok, reason = pr.verify_binding(forged, archive)
        self.assertFalse(ok)
        self.assertEqual(reason, pr.REASON_ROOT_HASH_MISMATCH)

    def test_binding_fields_strict(self):
        with self.assertRaises(pr.PolicyRootError):
            pr.PolicyBinding.from_mapping({"policy_id": "x"})
        with self.assertRaises(pr.PolicyRootError):
            pr.PolicyBinding.from_mapping(
                {
                    "policy_id": "p",
                    "policy_version": "v1",
                    "root_hash": "not-a-hash",
                    "section_name": "spend",
                    "section_hash": "f" * 64,
                }
            )

    def test_make_binding_unknown_section_rejected(self):
        with self.assertRaises(pr.PolicyRootError):
            pr.make_binding(POLICY_ID, "v1", sections_v1(), "nope")


class MandateConservationTests(unittest.TestCase):
    def make_ledger(self):
        archive, _ = archive_with_v1()
        return archive, MandateLedger.begin(
            archive, policy_id=POLICY_ID, policy_version="v1"
        )

    def test_fixture_conservation_events(self):
        _, ledger = self.make_ledger()
        self.assertEqual(ledger.capacity, 100)
        ledger.admit_actor("A")
        self.assertEqual(ledger.balances(), {"A": 100})
        self.assertTrue(ledger.check_invariant())
        ledger.admit_actor("B")
        receipt = ledger.allocate("A", "B", 30)
        self.assertEqual(ledger.balances(), {"A": 70, "B": 30})
        self.assertEqual(ledger.committed(), 0)
        self.assertEqual(ledger.live_unspent() + ledger.committed(), 100)
        receipt2 = ledger.commit_external("B", 18)
        self.assertEqual(ledger.balances(), {"A": 70, "B": 12})
        self.assertEqual(ledger.committed(), 18)
        self.assertEqual(ledger.live_unspent() + ledger.committed(), 100)
        for item in (receipt, receipt2):
            self.assertEqual(
                item["receipt_hash"],
                object_hash({k: v for k, v in item.items() if k != "receipt_hash"}),
            )

    def test_actor_subdivision_creates_no_capacity(self):
        _, ledger = self.make_ledger()
        ledger.admit_actor("A")
        for name in ("B", "C", "D"):
            ledger.admit_actor(name)
        self.assertEqual(ledger.live_unspent() + ledger.committed(), 100)
        ledger.allocate("A", "B", 30)
        ledger.allocate("B", "C", 10)
        ledger.allocate("A", "D", 5)
        self.assertEqual(ledger.balances(), {"A": 65, "B": 20, "C": 10, "D": 5})
        self.assertEqual(ledger.live_unspent() + ledger.committed(), 100)
        # Re-admission (rename/replace/spawn) grants no fresh capacity.
        ledger.admit_actor("B")
        ledger.admit_actor("E")
        self.assertEqual(ledger.balances()["B"], 20)
        self.assertEqual(ledger.balances()["E"], 0)
        self.assertEqual(ledger.live_unspent() + ledger.committed(), 100)

    def test_over_capacity_refused_atomically(self):
        _, ledger = self.make_ledger()
        ledger.admit_actor("A")
        ledger.admit_actor("B")
        ledger.allocate("A", "B", 30)
        before = ledger.state()
        with self.assertRaises(LedgerRefused):
            ledger.allocate("A", "B", 10_000)
        with self.assertRaises(LedgerRefused):
            ledger.commit_external("B", 31)
        with self.assertRaises(LedgerRefused):
            ledger.allocate("A", "nobody", 1)
        with self.assertRaises(LedgerRefused):
            ledger.commit_external("nobody", 1)
        with self.assertRaises(LedgerRefused):
            ledger.allocate("A", "B", 0)
        with self.assertRaises(LedgerRefused):
            ledger.allocate("A", "B", -5)
        with self.assertRaises(LedgerRefused):
            ledger.allocate("A", "B", True)
        with self.assertRaises(LedgerRefused):
            ledger.commit_external("B", 1.5)
        self.assertEqual(ledger.state(), before)
        self.assertTrue(ledger.check_invariant())

    def test_receipts_carry_exact_frozen_binding(self):
        archive, _ = archive_with_v1()
        ledger = MandateLedger.begin(archive, policy_id=POLICY_ID, policy_version="v1")
        ledger.admit_actor("A")
        ledger.admit_actor("B")
        first = ledger.allocate("A", "B", 30)
        second = ledger.commit_external("B", 18)
        expected = pr.make_binding(POLICY_ID, "v1", sections_v1(), "spend")
        for receipt in (first, second):
            self.assertEqual(receipt["binding"], expected.to_dict())
            binding = pr.PolicyBinding.from_mapping(receipt["binding"])
            self.assertEqual(
                pr.verify_binding(binding, archive), (True, pr.REASON_BINDING_VALID)
            )
        self.assertEqual(first["event"], "internal_allocation")
        self.assertEqual(second["event"], "external_consequence")

    def test_v1_ledger_receipts_verify_after_v2(self):
        archive, _ = archive_with_v1()
        ledger = MandateLedger.begin(archive, policy_id=POLICY_ID, policy_version="v1")
        ledger.admit_actor("A")
        ledger.admit_actor("B")
        receipt = ledger.allocate("A", "B", 30)
        archive.admit(POLICY_ID, "v2", sections_v2())
        binding = pr.PolicyBinding.from_mapping(receipt["binding"])
        self.assertEqual(
            pr.verify_binding(binding, archive), (True, pr.REASON_BINDING_VALID)
        )

    def test_ledger_begin_rejects_unknown_version(self):
        archive, _ = archive_with_v1()
        with self.assertRaises(LedgerRefused):
            MandateLedger.begin(archive, policy_id=POLICY_ID, policy_version="v9")

    def test_ledger_begin_requires_capacity_in_section(self):
        archive = pr.PolicyArchive()
        archive.admit("p", "v1", {"spend": {"unit": "abstract"}})
        with self.assertRaises(LedgerRefused):
            MandateLedger.begin(archive, policy_id="p", policy_version="v1")


if __name__ == "__main__":
    unittest.main()
