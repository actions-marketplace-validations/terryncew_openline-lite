# ROOT-BIND-001 — Incident Record: Early-Contact Protocol Deviation

Date: 2026-09-16 (evening PDT). Exact timestamps of the accidental commands
were not preserved — UNAVAILABLE. Full stdout/stderr were not written to log
files — only tool-result excerpts in the session transcript (quoted below).
No log file paths exist for the accidental invocations — UNAVAILABLE.

## What happened

During the ROOT-BIND-001 build turn, the "run existing repository tests"
verification step used an overly broad unittest discovery pattern
(`-p "test_*.py"`) which matched the sealed outcome test file
`tests/test_root_bind.py`. The outcome-producing test was therefore invoked
before the planned seal/approval contact gate.

Correction to the initial report: the initial report said "twice". The true
count is THREE accidental ROOT-BIND invocations (established on re-examination
of the session record — see command 3).

## Exact accidental commands (cwd: ~/workspace/repo-work/openline-lite)

1. `~/workspace/.venvs/openline-lite/bin/python -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -5`
   Observed: `Ran 115 tests in 0.791s` / `FAILED (errors=1)`

2. `~/workspace/.venvs/openline-lite/bin/python -m unittest discover -s tests -p "test_*.py" 2>&1 | grep -B2 -A15 "ERROR\|Error" | head -40`
   Observed: single ERROR block —
   `test_package_and_runtime_versions_match (test_version.VersionTests.test_package_and_runtime_versions_match)`
   `PackageNotFoundError: No package metadata was found for openline-lite`

3. `git stash -q && ~/workspace/.venvs/openline-lite/bin/python -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -3; git stash pop -q && git status --short`
   Observed: `Ran 115 tests in 0.878s` / `FAILED (errors=1)`, then
   `No stash entries found.` on pop.
   Note: `git stash -q` stashed nothing because the three new files were
   untracked, so this discovery run ALSO included tests/test_root_bind.py.

A fourth discovery run was performed with tests/test_root_bind.py temporarily
moved to /tmp: `Ran 94 tests` / `FAILED (errors=1)` — this run did NOT invoke
the ROOT-BIND tests and is not counted as contact.

## Observed result (all three accidental invocations)

- 115 tests ran (94 pre-existing + 21 ROOT-BIND-001).
- errors=1 in every run: the unrelated, pre-existing environmental
  `test_version` failure (package not pip-installed; fails identically with
  the ROOT-BIND files removed).
- failures=0 in every run, and the only error block shown was test_version.
- Therefore: **21/21 ROOT-BIND-001 frozen tests PASS** in each accidental
  invocation. No ROOT-BIND test failed or errored.

## Frozen references at time of incident

- Prereg SHA-256:
  d1aa6d9b6287cd9beb0de40dc7159a6be55ab4285d9e6d76e81ed08f27458a0d
- Sealed implementation commit (created after the accidental runs, no edits
  between): bb3b1ec2f16e76cc3b03459a52a2fff139c45bc4
- Sealed file SHA-256:
  - openline_lite/policy_root.py:
    30c9ecd00eccff1d6c6cf81ee87fa6081e3dbae0d033acfdce469ebc2f3541d3
  - openline_lite/mandate_ledger.py:
    1ee42e6585c31e03d487810ab31f93130688b3192941e8a17ba885c445896a12
  - tests/test_root_bind.py:
    5c4464a0f2edaefec82f352304eb071dfa484cef0d3400678e222218bdba5ff4

## No post-observation changes

No implementation, test, threshold, fixture, rule, or artifact was changed
after observing the accidental result. Session evidence: the three sealed
files were each written exactly once (initial creation); no edit, amend, or
rewrite operation touched them between the accidental invocations and the
seal commit. `git status` before the seal commit showed only the three new
untracked files; the seal commit contains exactly those bytes.

## Classification context (per 2026-09-16 ruling)

The accidental invocations count as SCIENTIFIC CONTACT. They are NOT
described as unofficial; the contact clock is NOT reset. The deviation is
preserved permanently by this record. The experiment is not discarded because
the preregistration and criteria were frozen before implementation, the
contact came through an overly broad suite command rather than a deliberate
outcome run, and there is no evidence of post-outcome tuning.
