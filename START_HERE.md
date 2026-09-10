# Start here with OpenLine

**Keep control of the work when the AI changes.**

OpenLine keeps evidence, acceptance rules, and authority outside the model. Start with a local example in **OpenLine Lite**, then choose the component for the job you actually need. You do not need to install the whole stack.

## 1. Run something now

This example answers: **when evidence is invalidated, which earlier decisions need another look?**

You need Git and Python 3.10–3.13. From a terminal on macOS or Linux:

```bash
git clone https://github.com/terryncew/openline-lite.git
cd openline-lite
python -m venv .venv
. .venv/bin/activate
python -m pip install .
python -m examples.impact
```

Already in this repository? Start at `python -m venv .venv`. On Windows PowerShell, replace the activation line with `.venv\Scripts\Activate.ps1`.

Installation needs internet. The example needs no model key, server, or database.

Look for these results:

| Result | Decision | What it means |
|---|---|---|
| `REOPEN` | `deploy-api` | Its required evidence was invalidated. Review it again. |
| `RETAIN` | `publish-benchmark` | Its complete required-evidence binding does not include the invalidated evidence. |
| `UNDETERMINED` | `publish-docs` | Its evidence binding is incomplete. Independence is not established. |

This example reports standing. It does **not** deploy, undo, or repair anything. [Read the example](examples/impact.py) or [inspect the trust boundary](TRUST_BOUNDARY.md).

## 2. Choose what you want to do

| Your task | Start with | First step |
|---|---|---|
| Check whether an action has the required evidence | **OpenLine Lite** | [Create a check pack and run `openline-check`](OPENLINE_CHECK.md). |
| Carry verified project facts into another model's context | **Lite handoff wrapper** | [Follow the project-state example](MODEL_HANDOFF.md). It verifies declared facts and file hashes; it does not call models or grant authority. |
| Let coding agents attempt improvements under your acceptance rules | **[Airlock](https://github.com/terryncew/openline-airlock)** | Follow its installation instructions, then run `airlock init` in your project and review the discovered checks. |
| Replace an agent while preserving permission and revocation history | **[Wallet](https://github.com/terryncew/openline-wallet)** | [Run the local provider-switch demo](https://github.com/terryncew/openline-wallet#try-the-provider-switch-demo). |
| Enforce permission before a proposed tool call executes | **[Receipt Gate](https://github.com/terryncew/openline-receipt-gate)** | [Run the guarded refund example](https://github.com/terryncew/openline-receipt-gate#five-minute-demo). |

“Receiver” means the system accepting the work or executing the action: your repository, service, or tool. Its rules determine what passes.

## 3. See a real worker replacement

In **APPROVED-JOB-LIVE-001**, Claude produced a verified partial code checkpoint. Its authority was revoked. Codex continued from that exact checkpoint and completed the remaining requirement under the same approved agreement. Independent checks accepted the final candidate.

The handoff carried the approved task and checked-out code state. It did not transfer Claude's chat or credentials.

- [Read the experiment and its limits](https://github.com/terryncew/openline-wallet/blob/main/APPROVED_JOB_LIVE_001.md).
- [Inspect the frozen receipts, patches, and provider logs](https://github.com/terryncew/openline-wallet/tree/main/proofs/approved-job-live-001/frozen).
- [See the successful real-host run](https://github.com/terryncew/openline-wallet/actions/runs/34413490635).

This is a bounded maintenance experiment with real providers. Provider absence was induced. It does not establish full session portability, production deployment safety, or protection from every outage. Running the Lite example above does not run this live-provider experiment.

## 4. Go deeper when needed

| Need | Reference |
|---|---|
| Understand Lite's architecture and limits | [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Verification](VERIFICATION.md) |
| Implement canonical receipts and signature verification | [OLP Wire Canon](https://github.com/terryncew/olp-wire-canon) |
| Capture evidence from an existing framework | [OpenTelemetry](https://github.com/terryncew/openline-otel) · [OpenAI Agents SDK](https://github.com/terryncew/openline-agents) · [LangGraph](https://github.com/terryncew/openline-langgraph) |
| Work with richer evidence dependencies | [Claim Graph](https://github.com/terryncew/openline-claim-graph) |
| Inspect research methods and experiments | [OpenLine Reports](https://github.com/terryncew/openline-reports) · [Audited Conjecture Engine](https://github.com/terryncew/openline-ace) |

These are early implementations and bounded experiments. Signed records establish integrity, not truth. Your checks must express your actual requirements, and consequential actions are protected only where the receiving system enforces the boundary. A rollback request is not proof that an effect was reversed.

**Start with one example. Add one boundary when your work needs it.**
