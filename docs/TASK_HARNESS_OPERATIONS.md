# pdx-local-ai Task Harness: Operations Guide (candidate)

This guide applies to the Windows local candidate.
This guide describes what the implementation does today; it makes no model-quality claims.

## 1. What it is

A bounded, resumable task layer on top of the existing search / memory / Engine. The host owns state,
budgets, authorization and acceptance. The agent proposes actions and artifacts; only the host verifier can
move a task to `succeeded`. `claimed_success` and `needs_review` are never success.

States: `draft → awaiting_approval → queued → running → awaiting_verification → succeeded`, plus
`waiting_input`, `needs_review`, `interrupted`, and terminal `failed`, `cancelled`, `timed_out`.

Templates (host-managed, versioned, grant no permissions): `doc_evidence_check` (gather → report),
`multihop_trace` (trace → report, `bounded_multihop`), `doc_memory_artifact` (gather → produce, always
`needs_review`, optional memory *proposal*).

## 2. Run it with an Agent

The stdio command is the same for every client: `pdx-local service` with the catalog, workspace, and principal.
Client files and the copy-paste prompts are in [Agent onboarding](AGENT_ONBOARDING.md).
`pdx-local agent config cursor --apply` writes the Cursor file; without `--apply` it only prints a preview. `pdx-local agent config preview --client ...` prints the others.
Do not give the agent connection `--can-approve-tasks`.

Service entry (stdio MCP). Task tools are always listed; `approve_task` / `review_task_result` are listed only if
the host grants the capability.

```json
{
  "mcpServers": {
    "pdx-local-ai": {
      "command": "C:/Example/LocalAI/pdx-local.exe",
      "args": ["service", "--catalog-path", "C:\\Users\\me\\AppData\\Local\\pdx-local-ai\\catalog.sqlite",
               "--workspace-id", "<workspace uuid>", "--principal-id", "me"]
    }
  }
}
```

Operator loop (the human, in a terminal; this is the approver/reviewer path):

```text
pdx-local task list --profile-dir <profile>
pdx-local task show <task_id> --profile-dir <profile>
pdx-local task approve <task_id> --profile-dir <profile>
pdx-local task review <task_id> --decision accept|reject|rework [--step-id report] [--note "..."]
pdx-local task cancel <task_id> --reason "..."
pdx-local task events <task_id>
pdx-local task purge-expired
```

Agent prompt that works with the envelope contract:

> Call `list_task_templates`, then `create_task` for `doc_evidence_check` with the source root id and your
> questions. Tell me the task id and wait for me to approve it. After approval, call `get_task_context`, then
> `dispatch_task_action` (always with a fresh `idempotency_key`; reuse the same key to retry), then
> `submit_task_result` for each step. Follow `envelope.next` and `envelope.available_actions`. Quote values
> verbatim from evidence; if you cannot, call `submit_task_result` with `declare_incomplete=true`.

An agent cannot approve its own task (`SELF_APPROVAL_DENIED`) and does not see the approver tools by default.
Giving the MCP connection approval authority is an explicit host decision:
`service --can-approve-tasks --can-review-tasks` (or env `PDX_LOCAL_CAN_APPROVE_TASKS` / `PDX_LOCAL_CAN_REVIEW_TASKS`).
Prefer leaving them off.

## 3. Bounds (defaults, `LIMITS` in `tasks/contracts.py`)

One active task per workspace, 32 pending; 32 steps, 64 tool actions, 3 attempts per step; tool result and
context packet 64 KiB; task input and candidate output 10 MiB; wall clock 30 min (starts at approval; paused time
is excluded); action 30 s, verification 10 s; 2000 events per task; retention 30 days after a terminal state.
Multihop: at most 3 hops, 2 branches per hop, one shared retrieval ledger per task attempt (never reset by
branching; elapsed is retrieval time actually consumed, not wall time).

## 4. Recovery model

Every action is TX1 (authorize, lease, idempotency, `intent` record) → execute outside any transaction → TX2
(fencing check, results). A crash between them leaves an `intent` operation that recovery marks `unknown`; the
same `idempotency_key` replays safely. A service that finds a `running` task with an expired lease (TTL 120 s)
marks it `interrupted`; `resume_task` re-checks authorization and takes the lease over. Cross-database effects
(memory proposal) use an outbox with retries; there is no exactly-once claim. Recovery runs when the task layer is
first used in a service process (the task database is created lazily).

## 5. Memory

`doc_memory_artifact` can *propose* durable memory (`pending_review`). Nothing is published automatically and the
proposal is only created after a human accepts the task.

## 6. Install, upgrade, uninstall, purge

`tasks.sqlite` lives in the profile directory. Upgrade backs it up (integrity-checked) to
`backups/tasks_backup_pre_upgrade_*.sqlite` and migrates it in the same guarded pipeline as the catalog; a failure
restores the old binaries and writes `MIGRATION_FAILED`. A newer on-disk schema is refused, never downgraded.
Uninstall keeps profile data; `purge` removes the whole profile including `tasks.sqlite` and `tasks/` workspaces.

## 7. Trust boundaries (read this)

- The CLI operator carries approver/reviewer rights. Anyone who can run `pdx-local task ...` as your OS user can
  approve tasks; that is an OS-level trust boundary, not something this layer can defend.
- Cross-principal and cross-workspace access return `TASK_NOT_FOUND`.
- Workspaces are task-private directories addressed only by generated ids; reparse points and links are refused.
  They are not a sandbox for executing code, and no arbitrary command execution exists in this layer.
- Candidate files are sealed through the public Engine façade (skill `pdx.task_candidate_seal`). Engine
  `completed_with_review` forces `needs_review`.

## 8. Inference engine and cache-isolation boundary

This layer does not run, bundle or configure an inference engine, and it does not claim any prefill, decode or
structured-output benefit. What it provides for a *separate* local engine:

- `get_task_context` returns `prefix` (deterministic: sorted keys, no timestamps, random ids or attempt numbers;
  contains only caller-declared source roots and params) and `volatile`. `prefix_sha256` is stable across calls and
  across tasks with the same parameters, so an engine with prefix caching can reuse it.
- Action schemas use a conservative JSON-schema subset (type, properties, required, enum, min/max, items,
  `additionalProperties:false`) suitable for grammar-constrained decoding.
- Cache isolation is the integrator's responsibility: never share a prefix cache across principals or
  workspaces. The prefix contains no principal data, but evidence windows (in `volatile`) do; do not cache or
  index them across tenants, and do not let one principal's engine session read another's cache.
- Utility measurements are in `scripts/task_harness_measure.py`; prefill/decode timing and structured-output
  compliance need an engine and are reported `not_measured`.

## 9. Known limits

Synthetic-corpus measurements only; one active task per workspace; the multihop first hop is the declared
entity; memory proposals are single-scope; the CLI cannot create task databases; Windows clean-OS verification of
the new package is not done.
