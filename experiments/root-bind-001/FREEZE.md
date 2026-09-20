# ROOT-BIND-001 — Freeze Record

## References

- Scientific commit (UNTOUCHED by this freeze): `bb3b1ec2f16e76cc3b03459a52a2fff139c45bc4`
  (branch `research/root-bind-001`, pushed to GitHub; remote SHA verified
  identical)
- This freeze/evidence commit references the scientific commit and modifies
  none of its files.
- Frozen preregistration SHA-256:
  `d1aa6d9b6287cd9beb0de40dc7159a6be55ab4285d9e6d76e81ed08f27458a0d`
  (`~/workspace/root-bind-001/PREREGISTRATION.md`, read-only)

## Sealed artifact hashes (scientific commit)

- `openline_lite/policy_root.py`:
  `30c9ecd00eccff1d6c6cf81ee87fa6081e3dbae0d033acfdce469ebc2f3541d3`
- `openline_lite/mandate_ledger.py`:
  `1ee42e6585c31e03d487810ab31f93130688b3192941e8a17ba885c445896a12`
- `tests/test_root_bind.py`:
  `5c4464a0f2edaefec82f352304eb071dfa484cef0d3400678e222218bdba5ff4`

## Capability-debt LOC accounting (frozen ceiling <= 350)

Method: AST-based count of non-blank, non-comment-only, non-docstring lines
in the two counted implementation modules (tests additional per contract;
docs/prereg excluded).

- `openline_lite/policy_root.py`: 131
- `openline_lite/mandate_ledger.py`: 124
- TOTAL: 255 non-test executable LOC — within the <= 350 ceiling.

No logic was moved to another executable file to evade the ceiling. The only
other new file is the test file (additional, not counted).

## Early-contact disclosure (summary; full record in INCIDENT.md)

Scientific contact occurred accidentally: three invocations of the outcome
test file via an overly broad `unittest discover -s tests -p "test_*.py"`
suite command, before the planned seal/approval contact gate. All three
showed 21/21 ROOT-BIND-001 tests passing. No implementation, test, threshold,
fixture, rule, or artifact was changed after observing that result; the
sealed bytes are identical to the contacted bytes. The deviation is preserved
permanently and is NOT described as unofficial; the contact clock was NOT
reset.

## Final classification

PASS_ROOT_BIND_001_WITH_PROTOCOL_DEVIATION_EARLY_CONTACT

## Frozen claim

Within the controlled single-authoritative-ledger fixture, the versioned
content-addressed owner-policy binding preserved exact historical
policy-version/section bindings across a later policy version, and internal
actor subdivision did not increase the mandate's conserved 100-unit authority
pool.

Protocol qualifier (carries with the claim): the outcome tests were
accidentally invoked before the planned seal/approval contact gate (three
invocations through an overly broad suite command); no code or test changes
followed that observation; the sealed artifact subsequently reproduced the
result (21/21 in a clean worktree pinned to the sealed commit). This is NOT
a pristine preregistered execution.

## Claim boundary

- One mandate, one authoritative in-memory ledger, fixed 100-unit capacity.
- No distributed receiver, consensus, networking, persistence, real-money,
  Stripe, blockchain, Wallet, Receipt Gate, or Airlock integration claims.
- No generic semantic delegation machinery was built or is claimed.
- Passing does not earn infrastructure standing; reuse requires two genuinely
  independent downstream consumers per the frozen reassessment point.
