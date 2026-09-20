# ROOT-BIND-001 — formatting-only integration derivative addendum

Date: 2026-09-17 (UTC)
Authorization: explicit operator authorization, "ROOT-BIND-001 FORMATTING-ONLY
INTEGRATION DERIVATIVE AUTHORIZED" (2026-09-16 PDT).

## Standing, unchanged

- Frozen verdict: **PASS_ROOT_BIND_001_WITH_PROTOCOL_DEVIATION_EARLY_CONTACT**
- Frozen claim: unchanged. See freeze record in this directory.
- The scientific artifact remains the exact file bytes at commit
  **bb3b1ec2f16e76cc3b03459a52a2fff139c45bc4**.
- The scientific hashes below remain the authoritative hashes for the frozen
  ROOT-BIND-001 result. They have not changed and were not re-recorded.

## Why this derivative exists

CI `lint` (`.github/workflows/ci.yml`) runs `ruff format --check` and failed
on the three new ROOT-BIND-001 files. Repairing the scientific files was
forbidden by the frozen protocol ruling, so this derivative was authorized as
a separate, additive, integration-only commit on top of the untouched freeze
commit f63d0921a8e0c60c2156b8291d79c0b70b28fe05.

This is NOT a reopening of ROOT-BIND-001, NOT a repair of its science, and NOT
a replacement of its frozen artifact.

## Scientific (authoritative) hashes — UNCHANGED, still the hashes of record

- openline_lite/policy_root.py:
  30c9ecd00eccff1d6c6cf81ee87fa6081e3dbae0d033acfdce469ebc2f3541d3
- openline_lite/mandate_ledger.py:
  1ee42e6585c31e03d487810ab31f93130688b3192941e8a17ba885c445896a12
- tests/test_root_bind.py:
  5c4464a0f2edaefec82f352304eb071dfa484cef0d3400678e222218bdba5ff4

## Formatter

- Command (repository-pinned, from .github/workflows/ci.yml):
  `ruff format openline_lite/policy_root.py openline_lite/mandate_ledger.py tests/test_root_bind.py`
- Version: ruff 0.15.2 (matches the CI-pinned `pip install ruff==0.15.2`)
- Applied to exactly the three authorized files. No manual edits, no semantic
  edits, no import redesign, no test changes, no cleanup beyond exactly what
  ruff format produced.

## Formatter diff (preserved verbatim before commit)

```
--- openline_lite/mandate_ledger.py
+++ openline_lite/mandate_ledger.py
@@ -78,7 +78,9 @@
         if section_name not in sections:
             raise LedgerRefused("ledger_section_unknown")
         section = sections[section_name]
-        capacity = section.get("mandate_capacity") if isinstance(section, dict) else None
+        capacity = (
+            section.get("mandate_capacity") if isinstance(section, dict) else None
+        )
         if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity <= 0:
             raise LedgerRefused("capacity_invalid")
         binding = make_binding(policy_id, policy_version, sections, section_name)

--- openline_lite/policy_root.py
+++ openline_lite/policy_root.py
@@ -165,9 +165,7 @@
         return tuple(version for (pid, version) in self._entries if pid == policy_id)


-def verify_binding(
-    binding: PolicyBinding, archive: PolicyArchive
-) -> tuple[bool, str]:
+def verify_binding(binding: PolicyBinding, archive: PolicyArchive) -> tuple[bool, str]:
     """Pure verification of a binding against the archive.

     Never falls back to the newest version: the claimed version must resolve

--- tests/test_root_bind.py
+++ tests/test_root_bind.py
@@ -218,9 +218,7 @@
         for item in (receipt, receipt2):
             self.assertEqual(
                 item["receipt_hash"],
-                object_hash(
-                    {k: v for k, v in item.items() if k != "receipt_hash"}
-                ),
+                object_hash({k: v for k, v in item.items() if k != "receipt_hash"}),
             )

     def test_actor_subdivision_creates_no_capacity(self):
@@ -268,9 +266,7 @@

     def test_receipts_carry_exact_frozen_binding(self):
         archive, _ = archive_with_v1()
-        ledger = MandateLedger.begin(
-            archive, policy_id=POLICY_ID, policy_version="v1"
-        )
+        ledger = MandateLedger.begin(archive, policy_id=POLICY_ID, policy_version="v1")
         ledger.admit_actor("A")
         ledger.admit_actor("B")
         first = ledger.allocate("A", "B", 30)
@@ -287,9 +283,7 @@

     def test_v1_ledger_receipts_verify_after_v2(self):
         archive, _ = archive_with_v1()
-        ledger = MandateLedger.begin(
-            archive, policy_id=POLICY_ID, policy_version="v1"
-        )
+        ledger = MandateLedger.begin(archive, policy_id=POLICY_ID, policy_version="v1")
```

## Equivalence gate

Mechanical AST comparison (ast.dump, position attributes excluded) of the exact
bb3b1ec2 file bytes against the formatted working-tree bytes:

- AST(policy_root before) == AST(policy_root after): PASS
- AST(mandate_ledger before) == AST(mandate_ledger after): PASS
- AST(test_root_bind before) == AST(test_root_bind after): PASS

Result: **AST EQUIVALENCE: PASS**

## Derivative integration test

`python -m unittest discover -s tests -p "test_root_bind.py" -v`
(explicitly authorized integration-equivalence check on the derivative artifact,
NOT a new ROOT-BIND scientific execution):

**21/21 PASS** (exit 0)

## Formatted (derivative) hashes — integration bytes only

- openline_lite/policy_root.py:
  e9521316b88058191e7727ebe3e142ad904c4bda24f31c83103b852a6cb96430
- openline_lite/mandate_ledger.py:
  7fba701624ddab26876a04858d452ca2ddff17f6de550f49c1d39b3fa9a5f395
- tests/test_root_bind.py:
  aab21f1264b94b84c667b6a19ae62d058832145646aeb722dce5c950007ce390

## Non-substitution statement

The merged/integration bytes in this derivative commit are a formatting-only
derivative produced solely to satisfy CI lint. They are NOT substituted
retroactively for the scientific artifact: the frozen ROOT-BIND-001 result,
verdict, claim, and scientific hashes remain bound to the exact bb3b1ec2 bytes
recorded above. The derivative commit sits on top of the untouched freeze
commit f63d0921; neither the scientific commit nor the freeze commit was
amended, rebased, squashed, or otherwise modified.
