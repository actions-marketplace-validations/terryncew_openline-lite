# ROOT-BIND-001 — Confirmation Run Record

This is a CONFIRMATORY REPRODUCTION of an already-contacted frozen artifact.
It is NOT a pristine first contact. See INCIDENT.md for the early-contact
protocol deviation, which is preserved permanently.

## Invocation

- Date: 2026-09-16 (PDT)
- Command: `python -m unittest discover -s tests -p "test_root_bind.py" -v`
- Working tree: clean `git worktree` checkout pinned to the sealed commit
  (no edits before or during the run; worktree removed afterwards)
- Git SHA: `bb3b1ec2f16e76cc3b03459a52a2fff139c45bc4`
- Branch: `research/root-bind-001`
- Python: 3.12.3
- cryptography: 47.0.0
- Platform: Linux-7.0.0-26-generic-x86_64-with-glibc2.39

Only the sealed ROOT-BIND-001 test file was invoked — no broad discovery.

## Result

- Ran 21 tests, OK, exit code 0, 0 failures, 0 errors.
- Durable logs: `logs/confirmation-run-stdout.txt`,
  `logs/confirmation-run-stderr.txt` (verbose per-test lines are on stderr,
  as unittest -v writes them).

## Classification

PASS_ROOT_BIND_001_WITH_PROTOCOL_DEVIATION_EARLY_CONTACT

The exact sealed commit reproduced all 21 frozen tests passing.
