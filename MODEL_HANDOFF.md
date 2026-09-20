# Verified model handoff wrapper

This is a small dogfood wrapper around OpenLine Lite's existing handoff ideas. It is not a new judge, planner, or model router.

Its job is narrower:

```text
verified project state
        ↓
bounded task packet
        ↓
Claude / Codex / other model
        ↓
structured candidate JSON
        ↓
receiver-owned local verifier
        ↓
COMMIT / QUARANTINE / DENY
        ↓
next verified project state
```

The next model does **not** inherit the previous model's prose as project truth. It receives only receiver-verified facts and file hashes from the last committed state, plus the new user task.

## What v1 verifies

A candidate may declare:

- files it changed or deleted;
- JSON facts with an exact evidence file, SHA-256, JSON Pointer, and expected value;
- natural-language claims bound to one or more declared facts;
- unresolved items.

The verifier independently checks the workspace file hashes and evidence pointers.

Natural-language claim text is never promoted into the next verified state. A binding such as `"The tests passed" -> tests_exit_zero` records what the model claimed and which verified fact it cited; it does not pretend OpenLine can prove semantic entailment or general truth.

`COMMIT` means every declared file state and fact checked out, every claim points only to verified facts, and the candidate declared no unresolved items.

`QUARANTINE` means the candidate is structurally valid but evidence is missing, stale, mismatched, unsupported, or unresolved.

`DENY` means the candidate is malformed, bound to the wrong task/state, exceeds a hard limit, or attempts to escape the receiver-owned workspace.

## Receiver boundary

Keep the handoff state/task files outside the model's writable tool scope, or mount that control directory read-only. The model should receive the task packet as input and write only its candidate JSON plus normal project outputs.

The wrapper does not decide whether a code change is good, discover missing evidence, infer whether prose follows from evidence, run tests, plan work, call a model provider, grant runtime authority, or reverse side effects.

It only decides what local, receiver-observed facts may become the next model's context.

## Install

```bash
pip install .
openline-handoff --help
```

## Start a project state

```bash
mkdir -p ~/.openline-handoff/my-project

openline-handoff init \
  --project-id my-project \
  --out ~/.openline-handoff/my-project/state.json
```

## Prepare one bounded task

Put the task in `task.txt`, then bind it to the exact verified state:

```bash
openline-handoff task \
  --state ~/.openline-handoff/my-project/state.json \
  --task-id redirect-fix-001 \
  --instructions task.txt \
  --out ~/.openline-handoff/my-project/task.json
```

Give `task.json` to Claude, Codex, or another model.

## Require one candidate JSON

The model must return `olp.model_candidate.v1`, for example:

```json
{
  "schema": "olp.model_candidate.v1",
  "task_id": "redirect-fix-001",
  "input_state_sha256": "<copy from task.packet.input_state_sha256>",
  "task_packet_sha256": "<copy from task.packet_sha256>",
  "producer": "claude",
  "changes": [
    {
      "path": "tests/test_redirect.py",
      "status": "present",
      "sha256": "<sha256 of exact current file bytes>"
    }
  ],
  "facts": [
    {
      "id": "focused_tests_exit_zero",
      "evidence_path": ".receipts/focused-tests.json",
      "evidence_sha256": "<sha256 of exact receipt bytes>",
      "pointer": "/exit_code",
      "expected": 0
    }
  ],
  "claims": [
    {
      "id": "focused_tests_passed",
      "text": "The focused tests passed.",
      "support_fact_ids": ["focused_tests_exit_zero"]
    }
  ],
  "unresolved": []
}
```

A deleted file is:

```json
{"path": "obsolete.py", "status": "absent", "sha256": null}
```

## Verify outside the model

```bash
openline-handoff verify \
  --state ~/.openline-handoff/my-project/state.json \
  --task ~/.openline-handoff/my-project/task.json \
  --candidate candidate.json \
  --workspace . \
  --out-dir ~/.openline-handoff/my-project/result
```

On `COMMIT`, use `result/state.json` as the next verified state. On `QUARANTINE` or `DENY`, no successor state is created.

A model can write “the tests passed,” but that sentence is not forwarded. If the receiver independently verifies the cited receipt hash and `/exit_code = 0`, the next state may carry only that fact.

That is the entire point of v1.

## Funes memory beneath the verified boundary

[Funes](https://github.com/huggingface/funes) can provide verbatim recall across Claude, Codex, Hermes, pi, and subagent sessions. OpenLine Lite does not treat that memory as verified state.

`openline-funes-handoff` captures the exact `funes recall` output, hashes it, records the Funes version/query/memory in a manifest, and binds that manifest hash into the ordinary OpenLine task packet. The recalled passages are then available to the model as historical context, but they cannot become the next model's verified state merely because they were recalled.

The boundary is:

```text
Funes recall (verbatim history, provenance)
        ↓
UNVERIFIED_MEMORY
        ↓
bounded OpenLine task
        ↓
Claude / Codex / other model
        ↓
normal candidate evidence requirements
        ↓
COMMIT / QUARANTINE / DENY
        ↓
verified state only
```

If old memory says “tests passed,” that may tell the model where to look. It does not make `tests_passed` a verified fact. The candidate must still point to a receiver-checkable receipt or other supported evidence.

### Create a task with Funes recall

Install Funes separately and make sure `funes --version` works. Then:

```bash
openline-funes-handoff task \
  --state ~/.openline-handoff/my-project/state.json \
  --task-id redirect-fix-002 \
  --instructions task.txt \
  --query "why did we choose the redirect handling this way" \
  --memory local \
  --out-dir ~/.openline-handoff/my-project/funes-task
```

The output directory contains:

- `task.json` — the normal OpenLine task packet;
- `recall.txt` — exact Funes recall bytes;
- `recall.json` — source/version/query/memory plus the recall SHA-256;
- `.sha256` sidecars for each artifact.

Give the model `task.json`, `recall.json`, and `recall.txt`. Keep the control directory outside the model's writable scope or mount it read-only.

Before use, the harness can recheck the bundle:

```bash
openline-funes-handoff verify-bundle \
  --task ~/.openline-handoff/my-project/funes-task/task.json \
  --recall-manifest ~/.openline-handoff/my-project/funes-task/recall.json \
  --recall ~/.openline-handoff/my-project/funes-task/recall.txt
```

This verifies that the recall bytes still match their manifest and that the exact manifest was bound into the task packet. It does not certify that recalled prose is current or true.

After the model produces its candidate, use the ordinary `openline-handoff verify` command. On `COMMIT`, the successor state contains only the receiver-verified facts and file hashes. A later Codex task may query the same Funes memory again, but Claude's recalled prose never silently becomes Codex's verified project state.

