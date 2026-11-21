"""TaskService: headless local task harness over the existing catalog, memory and Engine.

Transaction pattern for every mutating agent action:
  TX1  prelude  (auth, state, lease, idempotency, ``task_operation`` intent)   -> COMMIT
       execute  (retrieval / memory / workspace / Engine; no DB transaction held)
  TX2  apply    (fencing check, state recheck, results, operation completed)  -> COMMIT
A crash between TX1 and TX2 leaves an ``intent`` operation that recovery reconciles; it
never produces a half-recorded success.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator

from ..service.contracts import SecurityContext
from . import verifier as vf
from .context import (
    ContextAssembler,
    RetrievalLedger,
    accepted_parent_artifacts,
    build_envelope,
    current_attempt,
)
from .contracts import (
    AWAITING_APPROVAL,
    AWAITING_VERIFICATION,
    CANCELLED,
    CONTEXT_MODES,
    DRAFT,
    FAILED,
    INTERRUPTED,
    LIMITS,
    NEEDS_REVIEW,
    QUEUED,
    RUNNING,
    SUCCEEDED,
    TERMINAL_STATES,
    TIMED_OUT,
    WAITING_INPUT,
    TaskError,
    authorize,
    canonical_json,
    check_transition,
    normalize_query,
    sha256_json,
    sha256_text,
    utf8_len,
)
from .dispatcher import EngineAdapter, MemoryBackend, SearchBackend, clip_response, new_id
from .store import TASKS_DB_NAME, TaskStore, utc_iso
from .templates import ACTION_SCHEMAS, TEMPLATES, get_template, public_templates, template_digest, validate_params
from .workspace import TaskWorkspace

_NON_TERMINAL_PENDING = (DRAFT, AWAITING_APPROVAL, QUEUED, RUNNING, WAITING_INPUT, AWAITING_VERIFICATION,
                         NEEDS_REVIEW, INTERRUPTED)
_HINTS = {
    "retrieval": "search, then submit_step with selected_evidence_ids",
    "multihop": "search hop by hop (parent_hop_id + entity), then submit_step with chain and answer",
    "final": "submit_step with the final artifact",
}
_ACTIONS = ("search", "recall_memory", "recall_published_memory", "write_candidate", "submit_step")


@dataclass
class _Started:
    task: sqlite3.Row
    step: sqlite3.Row
    step_def: dict[str, Any]
    attempt: sqlite3.Row
    op_id: str
    token: int
    now: float
    extra: dict[str, Any]


@dataclass
class _Replay:
    response: dict[str, Any]


@dataclass
class _Deferred:
    error: TaskError


def _validate_idempotency_key(key: Any) -> str:
    if not isinstance(key, str) or not 16 <= len(key) <= 128:
        raise TaskError("TASK_VALIDATION_ERROR", "idempotency_key must be a string of 16..128 characters")
    return key


class TaskService:
    def __init__(self, *, store: TaskStore, workspace: TaskWorkspace, search: SearchBackend | None,
                 memory: MemoryBackend | None, engine: EngineAdapter,
                 clock: Callable[[], float] = time.time, owner_id: str | None = None,
                 fault_hook: Callable[[str], None] | None = None) -> None:
        self.store = store
        self.workspace = workspace
        self.search = search
        self.memory = memory
        self.engine = engine
        self.clock = clock
        self.owner_id = owner_id or f"svc-{uuid.uuid4()}"
        self.fault_hook = fault_hook
        self.assembler = ContextAssembler(store)
        self._shutting_down = False
        self._inflight = 0
        self._cond = threading.Condition()
        self._tokens: dict[str, int] = {}

    # ------------------------------------------------------------------ construction
    @classmethod
    def open(cls, profile_dir: Path, *, agent_service: Any = None, catalog: Any = None,
             engine_required: bool = True, clock: Callable[[], float] = time.time,
             fault_hook: Callable[[str], None] | None = None, run_recovery: bool = True) -> "TaskService":
        profile_dir = Path(profile_dir)
        store = TaskStore(profile_dir / TASKS_DB_NAME, clock=clock)
        workspace = TaskWorkspace(profile_dir / "tasks")
        cat = catalog if catalog is not None else (agent_service.catalog if agent_service is not None else None)
        service = cls(
            store=store, workspace=workspace,
            search=SearchBackend(agent_service) if agent_service is not None else None,
            memory=MemoryBackend(cat) if cat is not None else None,
            engine=EngineAdapter(profile_dir / "tasks", required=engine_required),
            clock=clock, fault_hook=fault_hook)
        if run_recovery:
            service.recover()
        return service

    def _fault(self, point: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(point)

    def _ev(self, conn: sqlite3.Connection, task_id: str, kind: str, payload: dict[str, Any], **kw: Any) -> None:
        self.store.append_event(conn, task_id, kind, payload, **kw)

    # ------------------------------------------------------------------ templates
    def list_task_templates(self, ctx: SecurityContext) -> dict[str, Any]:
        authorize(ctx, "list_task_templates")
        return {"contract": "pdx_local_task_v1", "templates": public_templates(),
                "limits": {k: LIMITS[k] for k in sorted(LIMITS)}}

    # ------------------------------------------------------------------ create / approve
    def create_task(self, ctx: SecurityContext, template_id: str, params: dict[str, Any], *,
                    context_mode: str | None = None, idempotency_key: str | None = None) -> dict[str, Any]:
        authorize(ctx, "create_task")
        template = get_template(template_id)
        normalized = validate_params(template_id, params)
        mode = context_mode or template["context_mode"]
        if mode not in CONTEXT_MODES:
            raise TaskError("TASK_VALIDATION_ERROR", "unsupported context_mode")
        has_multihop = any(s["kind"] == "multihop" for s in template["steps"])
        if has_multihop and mode != "bounded_multihop":
            raise TaskError("TASK_VALIDATION_ERROR", "this template requires bounded_multihop")
        if not has_multihop and mode == "bounded_multihop":
            raise TaskError("TASK_VALIDATION_ERROR", "bounded_multihop needs a multihop template")
        if idempotency_key is not None:
            _validate_idempotency_key(idempotency_key)
        if self.search is not None:
            enabled = set(self.search.roots_enabled(ctx, normalized["source_root_ids"]))
            missing = [r for r in normalized["source_root_ids"] if r not in enabled]
            if missing:
                raise TaskError("SOURCE_NOT_AUTHORIZED", "source root is not enabled in this workspace")
        request_sha = sha256_json({"t": template_id, "p": normalized, "m": mode})
        now = self.clock()
        with self.store.tx() as conn:
            if idempotency_key is not None:
                prior = conn.execute(
                    "SELECT task_id, request_sha256 FROM task WHERE workspace_id=? AND principal_id=? "
                    "AND idempotency_key=?", (ctx.workspace_id, ctx.principal_id, idempotency_key)).fetchone()
                if prior is not None:
                    if prior["request_sha256"] != request_sha:
                        raise TaskError("IDEMPOTENCY_CONFLICT", "idempotency key reused with different request")
                    return self._summary(conn, self.store.require_task(prior["task_id"], conn), replayed=True)
            pending = self.store.count_by_state(conn, ctx.workspace_id, _NON_TERMINAL_PENDING)
            if pending >= LIMITS["max_pending_tasks"]:
                raise TaskError("TASK_QUEUE_FULL", "pending task limit reached",
                                {"limit": LIMITS["max_pending_tasks"]})
            task_id = new_id()
            params_json = canonical_json(normalized)
            conn.execute(
                "INSERT INTO task(task_id, workspace_id, principal_id, creator_actor_kind, template_id, "
                "template_version, template_sha256, context_mode, params_json, params_sha256, state, "
                "state_version, created_at, updated_at, last_seen_epoch, deadline_epoch, input_bytes, "
                "idempotency_key, request_sha256) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (task_id, ctx.workspace_id, ctx.principal_id, ctx.actor_kind, template_id,
                 template["version"], template_digest(template_id), mode, params_json, sha256_text(params_json),
                 DRAFT, 1, utc_iso(now), utc_iso(now), now, now + LIMITS["task_wall_clock_seconds"],
                 len(params_json.encode("utf-8")), idempotency_key, request_sha))
            self._ev(conn, task_id, "task_created", {"template": template_id, "mode": mode,
                                                     "params_sha256": sha256_text(params_json)})
            for step in template["steps"]:
                conn.execute("INSERT INTO task_step(task_id, step_id, kind, depends_on_json, state) "
                             "VALUES (?,?,?,?,?)", (task_id, step["id"], step["kind"],
                                                    canonical_json(step["depends_on"]), "pending"))
            task = self.store.require_task(task_id, conn)
            self._advance_steps(conn, task, now)
            v = self.store.cas_state(conn, task_id, 1, AWAITING_APPROVAL, now=now)
            self._ev(conn, task_id, "state_changed", {"from": DRAFT, "to": AWAITING_APPROVAL, "state_version": v})
            return self._summary(conn, self.store.require_task(task_id, conn))

    def approve_task(self, ctx: SecurityContext, task_id: str, *,
                     expected_state_version: int | None = None) -> dict[str, Any]:
        now = self.clock()
        with self.store.tx() as conn:
            task = self.store.require_task(task_id, conn)
            authorize(ctx, "approve_task", task["workspace_id"], None)
            if ctx.actor_kind == "agent" and task["creator_actor_kind"] == "agent":
                raise TaskError("SELF_APPROVAL_DENIED", "an agent may not approve a task created by an agent")
            if expected_state_version is not None and expected_state_version != task["state_version"]:
                raise TaskError("TASK_STATE_CONFLICT", "state_version mismatch")
            check_transition(task["state"], QUEUED)
            conn.execute("INSERT INTO task_approval(task_id, params_sha256, approver_actor_kind, "
                         "approver_principal_id, approved_at) VALUES (?,?,?,?,?)",
                         (task_id, task["params_sha256"], ctx.actor_kind, ctx.principal_id, utc_iso(now)))
            conn.execute("UPDATE task SET deadline_epoch=? WHERE task_id=?",
                         (now + LIMITS["task_wall_clock_seconds"], task_id))  # budget starts at approval
            v = self.store.cas_state(conn, task_id, task["state_version"], QUEUED, now=now)
            self._ev(conn, task_id, "approval_granted", {"approver_kind": ctx.actor_kind,
                                                         "params_sha256": task["params_sha256"]})
            self._ev(conn, task_id, "state_changed", {"from": AWAITING_APPROVAL, "to": QUEUED, "state_version": v})
            return self._summary(conn, self.store.require_task(task_id, conn))

    def revoke_task_approval(self, ctx: SecurityContext, task_id: str) -> dict[str, Any]:
        now = self.clock()
        with self.store.tx() as conn:
            task = self.store.require_task(task_id, conn)
            authorize(ctx, "approve_task", task["workspace_id"], None)
            conn.execute("UPDATE task_approval SET revoked_at=? WHERE task_id=? AND revoked_at IS NULL",
                         (utc_iso(now), task_id))
            self._ev(conn, task_id, "approval_revoked", {"by": ctx.actor_kind}, terminal=True)
            if task["state"] not in TERMINAL_STATES:
                v = self.store.cas_state(conn, task_id, task["state_version"], CANCELLED,
                                         reason="approval_revoked", now=now)
                self._ev(conn, task_id, "state_changed", {"from": task["state"], "to": CANCELLED,
                                                          "state_version": v}, terminal=True)
                self.store.release_lease(conn, task_id, self.owner_id)
                conn.execute("UPDATE task_lease SET expires_at_epoch=0 WHERE task_id=?", (task_id,))
            return self._summary(conn, self.store.require_task(task_id, conn))

    # ------------------------------------------------------------------ steps / attempts
    def _template_steps(self, task: sqlite3.Row) -> list[dict[str, Any]]:
        return get_template(task["template_id"])["steps"]

    def _max_queries(self, task: sqlite3.Row, kind: str) -> int:
        if kind == "multihop":
            hops = int(json.loads(task["params_json"]).get("max_hops", LIMITS["max_hops"]))
            return (2 ** hops) - 1
        return 4

    def _new_attempt(self, conn: sqlite3.Connection, task: sqlite3.Row, step_id: str, kind: str,
                     parent_digests: dict[str, str], now: float, note: str | None = None) -> str:
        last = conn.execute("SELECT MAX(attempt_no) FROM task_attempt WHERE task_id=? AND step_id=?",
                            (task["task_id"], step_id)).fetchone()[0] or 0
        if last >= LIMITS["max_attempts_per_step"]:
            raise TaskError("ATTEMPT_LIMIT", "step attempt limit reached", {"step_id": step_id})
        attempt_id = new_id()
        conn.execute(
            "INSERT INTO task_attempt(attempt_id, task_id, step_id, attempt_no, state, parent_digests_json, "
            "rework_note, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (attempt_id, task["task_id"], step_id, last + 1, "active", canonical_json(parent_digests),
             note, utc_iso(now)))
        conn.execute("UPDATE task_step SET state='ready', current_attempt_id=? WHERE task_id=? AND step_id=?",
                     (attempt_id, task["task_id"], step_id))
        if kind in ("retrieval", "multihop"):
            RetrievalLedger.new(now, max_queries=self._max_queries(task, kind)).save(
                conn, task["task_id"], attempt_id)
        return attempt_id

    def _advance_steps(self, conn: sqlite3.Connection, task: sqlite3.Row, now: float) -> list[str]:
        """Promote pending steps whose dependencies are all accepted; return promoted step ids."""
        promoted: list[str] = []
        for step_def in self._template_steps(task):
            row = conn.execute("SELECT * FROM task_step WHERE task_id=? AND step_id=?",
                               (task["task_id"], step_def["id"])).fetchone()
            if row["state"] != "pending":
                continue
            digests: dict[str, str] = {}
            ready = True
            for dep in step_def["depends_on"]:
                dep_row = conn.execute("SELECT * FROM task_step WHERE task_id=? AND step_id=?",
                                       (task["task_id"], dep)).fetchone()
                if dep_row["state"] != "accepted":
                    ready = False
                    break
                att = conn.execute("SELECT artifact_sha256 FROM task_attempt WHERE attempt_id=?",
                                   (dep_row["current_attempt_id"],)).fetchone()
                digests[dep] = att["artifact_sha256"]
            if ready:
                self._new_attempt(conn, task, step_def["id"], step_def["kind"], digests, now)
                promoted.append(step_def["id"])
        return promoted

    def _active_step(self, conn: sqlite3.Connection, task: sqlite3.Row) -> tuple[sqlite3.Row, dict[str, Any]] | None:
        for step_def in self._template_steps(task):
            row = conn.execute("SELECT * FROM task_step WHERE task_id=? AND step_id=?",
                               (task["task_id"], step_def["id"])).fetchone()
            if row["state"] in ("ready", "in_progress"):
                return row, step_def
        return None

    # ------------------------------------------------------------------ envelope / summary
    def _envelope(self, conn: sqlite3.Connection, task: sqlite3.Row) -> dict[str, Any]:
        active = self._active_step(conn, task) if task["state"] in (QUEUED, RUNNING) else None
        step_id = active[0]["step_id"] if active else None
        attempt = current_attempt(conn, task["task_id"], step_id) if step_id else None
        ledger_view: dict[str, Any] = {}
        evidence_ids: list[str] = []
        hop_ids: list[str] = []
        if attempt is not None:
            if conn.execute("SELECT 1 FROM task_ledger WHERE task_id=? AND attempt_id=?",
                            (task["task_id"], attempt["attempt_id"])).fetchone():
                ledger_view = RetrievalLedger.load(conn, task["task_id"], attempt["attempt_id"]).public(self.clock())
            evidence_ids = [r[0] for r in conn.execute(
                "SELECT evidence_id FROM task_evidence WHERE task_id=? AND attempt_id=? ORDER BY created_at",
                (task["task_id"], attempt["attempt_id"]))]
            hop_ids = [r[0] for r in conn.execute(
                "SELECT hop_id FROM task_hop WHERE task_id=? AND attempt_id=? ORDER BY hop_no, created_at",
                (task["task_id"], attempt["attempt_id"]))]
        kind = active[1]["kind"] if active else None
        return build_envelope(
            task, step_id, attempt, ledger_view, evidence_ids=evidence_ids, hop_ids=hop_ids,
            actions_left=max(0, LIMITS["max_tool_actions"] - int(task["action_count"])),
            next_step=_HINTS.get(kind or "", "no action required" if task["state"] != QUEUED else "dispatch first action"))

    def _summary(self, conn: sqlite3.Connection, task: sqlite3.Row, *, replayed: bool = False) -> dict[str, Any]:
        steps = []
        for r in conn.execute("SELECT * FROM task_step WHERE task_id=?", (task["task_id"],)):
            att = conn.execute("SELECT attempt_no, state, artifact_sha256, incomplete, stop_reason FROM task_attempt "
                               "WHERE attempt_id=?", (r["current_attempt_id"],)).fetchone() \
                if r["current_attempt_id"] else None
            steps.append({"step_id": r["step_id"], "kind": r["kind"], "state": r["state"],
                          "attempt": dict(att) if att else None})
        verdict_row = conn.execute("SELECT payload_json FROM task_event WHERE task_id=? AND kind='verification' "
                                   "ORDER BY seq DESC LIMIT 1", (task["task_id"],)).fetchone()
        artifacts = [dict(r) for r in conn.execute(
            "SELECT name, sha256, size_bytes, origin, step_id, attempt_id FROM task_artifact WHERE task_id=? "
            "ORDER BY created_at", (task["task_id"],))]
        return {
            "task_id": task["task_id"], "template_id": task["template_id"],
            "template_version": task["template_version"], "context_mode": task["context_mode"],
            "state": task["state"], "state_version": task["state_version"],
            "terminal_reason": task["terminal_reason"], "created_at": task["created_at"],
            "updated_at": task["updated_at"], "params": json.loads(task["params_json"]),
            "steps": sorted(steps, key=lambda s: s["step_id"]), "artifacts": artifacts,
            "verification": json.loads(verdict_row[0]) if verdict_row else None,
            "retain_until": task["retain_until"], "replayed": replayed,
            "envelope": self._envelope(conn, task),
        }

    # ------------------------------------------------------------------ reads
    def get_task(self, ctx: SecurityContext, task_id: str) -> dict[str, Any]:
        conn = self.store.conn
        task = self.store.require_task(task_id, conn)
        authorize(ctx, "get_task", task["workspace_id"], task["principal_id"])
        return self._summary(conn, task)

    def list_tasks(self, ctx: SecurityContext, *, states: list[str] | None = None, limit: int = 20) -> dict[str, Any]:
        authorize(ctx, "list_tasks")
        limit = max(1, min(50, int(limit)))
        clauses, args = ["workspace_id=?"], [ctx.workspace_id]
        if not ctx.is_admin:
            clauses.append("principal_id=?")
            args.append(ctx.principal_id)
        if states:
            clauses.append(f"state IN ({','.join('?' for _ in states)})")
            args.extend(states)
        rows = self.store.conn.execute(
            f"SELECT task_id, template_id, state, state_version, created_at, updated_at FROM task "
            f"WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT ?", (*args, limit)).fetchall()
        return {"tasks": [dict(r) for r in rows]}

    def get_task_events(self, ctx: SecurityContext, task_id: str, *, after_seq: int = 0, limit: int = 100) -> dict[str, Any]:
        conn = self.store.conn
        task = self.store.require_task(task_id, conn)
        authorize(ctx, "get_task_events", task["workspace_id"], task["principal_id"])
        limit = max(1, min(200, int(limit)))
        rows = conn.execute("SELECT seq, ts, kind, origin, step_id, attempt_id, payload_json, truncated FROM task_event "
                            "WHERE task_id=? AND seq>? ORDER BY seq LIMIT ?", (task_id, int(after_seq), limit)).fetchall()
        return {"task_id": task_id, "events": [{**{k: r[k] for k in ("seq", "ts", "kind", "origin", "step_id",
                                                                      "attempt_id", "truncated")},
                                                "payload": json.loads(r["payload_json"])} for r in rows]}

    def get_task_context(self, ctx: SecurityContext, task_id: str, step_id: str | None = None) -> dict[str, Any]:
        conn = self.store.conn
        task = self.store.require_task(task_id, conn)
        authorize(ctx, "get_task_context", task["workspace_id"], task["principal_id"])
        if task["state"] not in (QUEUED, RUNNING):
            raise TaskError("ACTION_NOT_ALLOWED", f"no context available in state {task['state']}")
        active = self._active_step(conn, task)
        if active is None or (step_id is not None and step_id != active[0]["step_id"]):
            raise TaskError("STEP_NOT_READY", "requested step is not the active step")
        attempt = current_attempt(conn, task_id, active[0]["step_id"])
        ledger = None
        if conn.execute("SELECT 1 FROM task_ledger WHERE task_id=? AND attempt_id=?",
                        (task_id, attempt["attempt_id"])).fetchone():
            ledger = RetrievalLedger.load(conn, task_id, attempt["attempt_id"])
        packet = self.assembler.assemble(conn, task, active[0]["step_id"], self.clock(), ledger=ledger)
        try:
            self._record_context_measurement(conn, task, attempt, active[0]["step_id"], ledger, packet)
        except Exception:
            return packet
        return packet

    def _record_context_measurement(self, conn: sqlite3.Connection, task: sqlite3.Row,
                                    attempt: sqlite3.Row, step_id: str,
                                    ledger: RetrievalLedger | None, packet: dict[str, Any]) -> None:
        """Best-effort measurement row. A duplicate packet does not re-read the catalog."""
        digest = packet["context_sha256"]
        existing = conn.execute(
            "SELECT 1 FROM task_context_measurement WHERE attempt_id=? AND step_id=? AND context_sha256=?",
            (attempt["attempt_id"], step_id, digest)).fetchone()
        if existing is not None:
            return
        windows = packet["volatile"]["evidence_windows"]
        eligible, error = self._eligible_file_bytes(task)
        remaining = ledger.public(self.clock()) if ledger is not None else None
        hop_count = int(conn.execute(
            "SELECT COUNT(*) FROM task_hop WHERE task_id=? AND attempt_id=? AND step_id=?",
            (task["task_id"], attempt["attempt_id"], step_id)).fetchone()[0])
        try:
            conn.execute(
                """INSERT INTO task_context_measurement (
                       measurement_id, task_id, attempt_id, step_id, context_mode,
                       prefix_sha256, prefix_bytes, context_sha256, context_bytes,
                       evidence_window_count, evidence_window_bytes, omitted_count,
                       eligible_file_bytes, ledger_queries, hop_count, ledger_remaining_json,
                       retrieval_terminal_reason, task_state, measurement_error,
                       provider_name, provider_input_tokens, provider_output_tokens
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (str(uuid.uuid4()), task["task_id"], attempt["attempt_id"], step_id, task["context_mode"],
                 packet["prefix_sha256"], utf8_len(canonical_json(packet["prefix"])),
                 digest, int(packet["context_bytes"]),
                 len(windows), sum(utf8_len(str(item["text"])) for item in windows),
                 int(packet["volatile"]["omitted_count"]),
                 eligible, int(ledger.data["queries"]) if ledger is not None else 0, hop_count,
                 None if remaining is None else canonical_json(remaining),
                 self._retrieval_terminal_reason(conn, task["task_id"], attempt["attempt_id"], step_id),
                 task["state"], error, None, None, None))
        except sqlite3.IntegrityError:
            raced = conn.execute(
                "SELECT 1 FROM task_context_measurement WHERE attempt_id=? AND step_id=? AND context_sha256=?",
                (attempt["attempt_id"], step_id, digest)).fetchone()
            if raced is None:
                raise

    def _retrieval_terminal_reason(self, conn: sqlite3.Connection, task_id: str, attempt_id: str,
                                   step_id: str) -> str | None:
        """Host stop code for the latest hop on this step. Empty only when no hop exists."""
        row = conn.execute(
            """SELECT stop_reason, status FROM task_hop
               WHERE task_id=? AND attempt_id=? AND step_id=?
               ORDER BY hop_no DESC, created_at DESC LIMIT 1""",
            (task_id, attempt_id, step_id)).fetchone()
        if row is None:
            return None
        if row["stop_reason"]:
            return str(row["stop_reason"])
        return str(row["status"])

    def _eligible_file_bytes(self, task: sqlite3.Row) -> tuple[int | None, str | None]:
        catalog = None
        if self.search is not None:
            catalog = self.search.agent_service.catalog
        elif self.memory is not None:
            catalog = self.memory.catalog
        if catalog is None:
            return None, "CATALOG_UNAVAILABLE"
        roots = list(json.loads(task["params_json"]).get("source_root_ids") or [])
        if not roots:
            return 0, None
        marks = ",".join("?" for _ in roots)
        try:
            row = catalog.conn.execute(
                f"""SELECT COALESCE(SUM(sv.size_bytes), 0)
                    FROM file_record f
                    JOIN source_version sv ON sv.source_version_id = f.current_source_version_id
                    JOIN file_acl a ON a.file_record_id = f.file_record_id
                         AND a.workspace_id = f.workspace_id
                    WHERE f.workspace_id=? AND a.principal_id=? AND a.can_read=1
                      AND f.catalog_status='active' AND f.source_root_id IN ({marks})""",
                (task["workspace_id"], task["principal_id"], *roots)).fetchone()
        except Exception:
            return None, "CATALOG_READ_FAILED"
        return int(row[0]), None

    # ------------------------------------------------------------------ action prelude
    def _begin_action(self, conn: sqlite3.Connection, ctx: SecurityContext, task_id: str, action: str,
                      idem_key: str, request_sha: str, expected_sv: int | None,
                      step_id: str | None = None) -> _Started | _Replay | _Deferred:
        task = self.store.require_task(task_id, conn)
        authorize(ctx, "dispatch_task_action", task["workspace_id"], task["principal_id"])
        if self._shutting_down:
            raise TaskError("TASK_SHUTTING_DOWN", "service is shutting down")
        op = conn.execute("SELECT * FROM task_operation WHERE task_id=? AND idempotency_key=?",
                          (task_id, idem_key)).fetchone()
        if op is not None:
            if op["request_sha256"] != request_sha or op["action"] != action:
                raise TaskError("IDEMPOTENCY_CONFLICT", "idempotency key reused with a different request")
            if op["state"] == "completed":
                return _Replay(json.loads(op["response_json"]))
        now = self.clock()
        if task["state"] in TERMINAL_STATES:
            raise TaskError("TASK_INVALID_TRANSITION", f"task is {task['state']}")
        if task["state"] not in (QUEUED, RUNNING):
            raise TaskError("ACTION_NOT_ALLOWED", f"actions are not accepted in state {task['state']}")
        if now + 5.0 < float(task["last_seen_epoch"]):
            v = self.store.cas_state(conn, task_id, task["state_version"], NEEDS_REVIEW,
                                     reason="clock_untrusted", now=float(task["last_seen_epoch"]))
            self._ev(conn, task_id, "state_changed", {"from": task["state"], "to": NEEDS_REVIEW,
                                                      "reason": "clock_untrusted", "state_version": v})
            return _Deferred(TaskError("CLOCK_UNTRUSTED", "system clock moved backwards; task moved to review"))
        if now > float(task["deadline_epoch"]):
            v = self.store.cas_state(conn, task_id, task["state_version"], TIMED_OUT, reason="deadline", now=now)
            self._ev(conn, task_id, "state_changed", {"from": task["state"], "to": TIMED_OUT, "state_version": v},
                     terminal=True)
            conn.execute("UPDATE task_lease SET expires_at_epoch=0 WHERE task_id=?", (task_id,))
            return _Deferred(TaskError("TASK_DEADLINE_EXCEEDED", "task wall-clock budget exhausted"))
        appr = conn.execute("SELECT * FROM task_approval WHERE task_id=?", (task_id,)).fetchone()
        if appr is None or appr["revoked_at"] is not None or appr["params_sha256"] != task["params_sha256"]:
            raise TaskError("TASK_AUTH_REVOKED", "task approval is missing, revoked or no longer matches")
        if expected_sv is not None and expected_sv != task["state_version"]:
            raise TaskError("TASK_STATE_CONFLICT", "state_version mismatch",
                            {"state_version": task["state_version"]})
        if op is None and int(task["action_count"]) >= LIMITS["max_tool_actions"]:
            raise TaskError("ACTION_BUDGET_EXCEEDED", "tool action budget exhausted")
        if task["state"] == QUEUED:
            active_n = self.store.count_by_state(conn, task["workspace_id"], (RUNNING, AWAITING_VERIFICATION))
            if active_n >= LIMITS["max_active_tasks"]:
                raise TaskError("ACTIVE_TASK_LIMIT", "another task is already active in this workspace")
        # lease: first dispatch or same owner only; takeover is resume_task's job
        token = self.store.acquire_lease(conn, task_id, self.owner_id, allow_takeover=False)
        self._tokens[task_id] = token
        if task["state"] == QUEUED:
            v = self.store.cas_state(conn, task_id, task["state_version"], RUNNING, now=now)
            self._ev(conn, task_id, "state_changed", {"from": QUEUED, "to": RUNNING, "state_version": v})
        active = self._active_step(conn, task)
        if active is None:
            raise TaskError("STEP_NOT_READY", "no active step")
        step_row, step_def = active
        if step_id is not None and step_id != step_row["step_id"]:
            raise TaskError("STEP_NOT_READY", "requested step is not the active step")
        if action not in step_def["actions"]:
            raise TaskError("ACTION_NOT_ALLOWED", f"action '{action}' is not available in step '{step_row['step_id']}'")
        attempt = current_attempt(conn, task_id, step_row["step_id"])
        conn.execute("UPDATE task_step SET state='in_progress' WHERE task_id=? AND step_id=?",
                     (task_id, step_row["step_id"]))
        if op is None:
            op_id = new_id()
            conn.execute(
                "INSERT INTO task_operation(operation_id, task_id, attempt_id, step_id, action, idempotency_key, "
                "request_sha256, state, fencing_token, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (op_id, task_id, attempt["attempt_id"], step_row["step_id"], action, idem_key, request_sha,
                 "intent", token, utc_iso(now), utc_iso(now)))
            conn.execute("UPDATE task SET action_count=action_count+1 WHERE task_id=?", (task_id,))
        else:
            op_id = op["operation_id"]
            conn.execute("UPDATE task_operation SET state='intent', fencing_token=?, updated_at=? WHERE operation_id=?",
                         (token, utc_iso(now), op_id))
        self.store.touch(conn, task_id, now)
        self._ev(conn, task_id, "action_intent", {"action": action, "operation_id": op_id},
                 attempt_id=attempt["attempt_id"], step_id=step_row["step_id"])
        fresh = self.store.require_task(task_id, conn)
        return _Started(fresh, step_row, step_def, attempt, op_id, token, now, {})

    def _finish_op(self, conn: sqlite3.Connection, op_id: str, state: str, response: dict[str, Any] | None) -> None:
        conn.execute("UPDATE task_operation SET state=?, response_json=?, updated_at=? WHERE operation_id=?",
                     (state, canonical_json(response) if response is not None else None,
                      utc_iso(self.clock()), op_id))

    def _require_live(self, conn: sqlite3.Connection, started: _Started) -> sqlite3.Row:
        """TX2 guard: fencing token valid and the task still running."""
        self.store.require_fence(conn, started.task["task_id"], self.owner_id, started.token)
        task = self.store.require_task(started.task["task_id"], conn)
        if task["state"] != RUNNING:
            conn.execute("UPDATE task_operation SET state='failed', updated_at=? WHERE operation_id=?",
                         (utc_iso(self.clock()), started.op_id))
            raise TaskError("TASK_INVALID_TRANSITION", f"task became {task['state']} during the action")
        return task

    def _record_rejection(self, task_id: str, action: str, err: TaskError) -> None:
        try:
            with self.store.tx() as conn:
                task = self.store.get_task(task_id, conn)
                if task is None or task["state"] in TERMINAL_STATES:
                    return
                active = self._active_step(conn, task)
                attempt = current_attempt(conn, task_id, active[0]["step_id"]) if active else None
                self._ev(conn, task_id, "action_rejected",
                         {"action": action, "code": err.code, "message": err.message[:300]},
                         origin=getattr(err, "origin", "local_policy"),
                         attempt_id=attempt["attempt_id"] if attempt else None,
                         step_id=active[0]["step_id"] if active else None)
                if attempt is not None and action == "submit_step" and err.code == "RESULT_REJECTED":
                    n = conn.execute("SELECT COUNT(*) FROM task_event WHERE task_id=? AND attempt_id=? AND "
                                     "kind='action_rejected' AND payload_json LIKE '%RESULT_REJECTED%'",
                                     (task_id, attempt["attempt_id"])).fetchone()[0]
                    if n >= 5 and task["state"] == RUNNING:
                        v = self.store.cas_state(conn, task_id, task["state_version"], NEEDS_REVIEW,
                                                 reason="attempt_limit")
                        self._ev(conn, task_id, "state_changed", {"from": RUNNING, "to": NEEDS_REVIEW,
                                                                  "reason": "attempt_limit", "state_version": v})
                        conn.execute("UPDATE task_lease SET expires_at_epoch=0 WHERE task_id=?", (task_id,))
        except Exception:
            pass

    # ------------------------------------------------------------------ public action entry points
    def dispatch_task_action(self, ctx: SecurityContext, task_id: str, action: str, arguments: dict[str, Any] | None,
                             idempotency_key: str, *, expected_state_version: int | None = None) -> dict[str, Any]:
        if action not in _ACTIONS:
            raise TaskError("ACTION_NOT_ALLOWED", "unknown action")
        return self._dispatch(ctx, task_id, action, arguments, idempotency_key, expected_state_version, None)

    def _dispatch(self, ctx: SecurityContext, task_id: str, action: str, arguments: dict[str, Any] | None,
                  idempotency_key: str, expected_state_version: int | None, step_hint: str | None) -> dict[str, Any]:
        if action not in _ACTIONS:
            raise TaskError("ACTION_NOT_ALLOWED", "unknown action")
        args = dict(arguments or {})
        idem = _validate_idempotency_key(idempotency_key)
        err = sorted(Draft202012Validator(ACTION_SCHEMAS[action]).iter_errors(args), key=lambda e: list(e.path))
        if err:
            raise TaskError("TASK_VALIDATION_ERROR", f"invalid arguments: {err[0].message}")
        request_sha = sha256_json({"a": action, "args": args, "s": step_hint})
        with self._cond:
            if self._shutting_down:
                raise TaskError("TASK_SHUTTING_DOWN", "service is shutting down")
            self._inflight += 1
        try:
            try:
                out = self._run_action(ctx, task_id, action, args, idem, request_sha, expected_state_version,
                                       step_hint)
            except TaskError as exc:
                if exc.code not in ("TASK_NOT_FOUND", "TASK_PERMISSION_DENIED", "LEASE_HELD", "LEASE_LOST",
                                    "TASK_STATE_CONFLICT", "IDEMPOTENCY_CONFLICT", "TASK_SHUTTING_DOWN"):
                    self._record_rejection(task_id, action, exc)
                raise
            self._after_commit(task_id)
            return out
        finally:
            with self._cond:
                self._inflight -= 1
                self._cond.notify_all()

    def _after_commit(self, task_id: str) -> None:
        """Run cross-database side effects (memory proposals) after the task transaction committed."""
        from . import recovery
        try:
            recovery.process_outbox(self, task_id)
        except Exception:
            pass

    def submit_task_result(self, ctx: SecurityContext, task_id: str, step_id: str, artifact: dict[str, Any],
                           idempotency_key: str, *, declare_incomplete: bool = False, reason: str | None = None,
                           expected_state_version: int | None = None) -> dict[str, Any]:
        args: dict[str, Any] = {"artifact": artifact}
        if declare_incomplete:
            args["declare_incomplete"] = True
        if reason is not None:
            args["reason"] = reason
        return self._dispatch(ctx, task_id, "submit_step", args, idempotency_key, expected_state_version, step_id)

    def _run_action(self, ctx: SecurityContext, task_id: str, action: str, args: dict[str, Any], idem: str,
                    request_sha: str, expected_sv: int | None, step_hint: str | None) -> dict[str, Any]:
        prep: dict[str, Any] = {}
        with self.store.tx() as conn:
            started = self._begin_action(conn, ctx, task_id, action, idem, request_sha, expected_sv, step_hint)
            if isinstance(started, _Started):
                # action-specific validation inside TX1 so failures roll back intent and lease changes
                if action == "search":
                    prep = self._prep_search(conn, ctx, started, args)
                elif action == "recall_memory":
                    prep = self._prep_recall(started)
                elif action == "recall_published_memory":
                    prep = self._prep_recall(started)
                elif action == "write_candidate":
                    prep = self._prep_write(conn, started, args)
                else:
                    prep = self._prep_submit(conn, started, args)
        if isinstance(started, _Replay):
            with self.store.tx() as conn:
                task = self.store.require_task(task_id, conn)
                return {"result": started.response, "envelope": self._envelope(conn, task), "replayed": True}
        if isinstance(started, _Deferred):
            raise started.error
        self._fault("after_intent")
        try:
            if action == "search":
                return self._do_search(ctx, started, args, prep)
            if action == "recall_memory":
                return self._do_recall(ctx, started, args, prep)
            if action == "recall_published_memory":
                return self._do_published_recall(ctx, started, args)
            if action == "write_candidate":
                return self._do_write(started, args, prep)
            return self._do_submit(ctx, started, args, prep)
        except TaskError as exc:
            if exc.code in ("LEASE_LOST",):
                raise
            with self.store.tx() as conn:
                self._finish_op(conn, started.op_id, "failed", {"error": exc.code})
            raise

    # ------------------------------------------------------------------ search
    def _prep_search(self, conn: sqlite3.Connection, ctx: SecurityContext, st: _Started,
                     args: dict[str, Any]) -> dict[str, Any]:
        if self.search is None:
            raise TaskError("SOURCE_NOT_AUTHORIZED", "retrieval backend unavailable")
        task, step_def = st.task, st.step_def
        params = json.loads(task["params_json"])
        roots = params["source_root_ids"]
        enabled = set(self.search.roots_enabled(ctx, roots))
        if any(r not in enabled for r in roots):
            raise TaskError("SOURCE_NOT_AUTHORIZED", "a task source root is no longer enabled")
        ledger = RetrievalLedger.load(conn, task["task_id"], st.attempt["attempt_id"])
        query = args["query"]
        qn = normalize_query(query)
        parent_id, entity = args.get("parent_hop_id"), args.get("entity")
        hops = conn.execute("SELECT * FROM task_hop WHERE task_id=? AND attempt_id=?",
                            (task["task_id"], st.attempt["attempt_id"])).fetchall()
        by_id = {h["hop_id"]: h for h in hops}
        pins_for_key = ""
        if step_def["kind"] == "multihop":
            max_hops = int(params.get("max_hops", LIMITS["max_hops"]))
            if parent_id is None:
                if any(h["parent_hop_id"] is None for h in hops):
                    raise TaskError("HOP_DUPLICATE", "the first hop already exists; continue from a parent hop")
                if entity is not None and normalize_query(entity) != normalize_query(params["start_entity"]):
                    raise TaskError("HOP_UNGROUNDED", "first hop must use the declared start_entity")
                entity = params["start_entity"]
                hop_no = 1
            else:
                parent = by_id.get(parent_id)
                if parent is None:
                    raise TaskError("HOP_UNGROUNDED", "unknown parent hop")
                if entity is None:
                    raise TaskError("HOP_UNGROUNDED", "follow-up hops must name the entity found in the parent hop")
                hop_no = int(parent["hop_no"]) + 1
                if hop_no > max_hops:
                    raise TaskError("HOP_LIMIT", "max_hops reached", {"stop_reason": "hop_limit"})
                if int(ledger.data["branches"].get(parent_id, 0)) >= LIMITS["max_branches_per_hop"]:
                    raise TaskError("BRANCH_LIMIT", "branch limit for this hop reached")
                texts = " ".join(r[0] for r in conn.execute(
                    "SELECT text FROM task_evidence WHERE task_id=? AND attempt_id=? AND hop_id=?",
                    (task["task_id"], st.attempt["attempt_id"], parent_id)))
                if normalize_query(entity) not in normalize_query(texts):
                    raise TaskError("HOP_UNGROUNDED", "entity does not appear in the parent hop evidence")
                vers = sorted({r[0] for r in conn.execute(
                    "SELECT source_version_id FROM task_evidence WHERE task_id=? AND attempt_id=? AND hop_id=?",
                    (task["task_id"], st.attempt["attempt_id"], parent_id))})
                pins_for_key = ",".join(vers)
            if normalize_query(entity) not in qn:
                raise TaskError("HOP_UNGROUNDED", "query must mention the grounded entity")
            queries_left = max(1, max_hops - hop_no + 1)
        else:
            if parent_id is not None or entity is not None:
                raise TaskError("TASK_VALIDATION_ERROR", "parent_hop_id/entity are only valid in multihop steps")
            hop_no = 1
            queries_left = max(1, int(ledger.data["max_queries"]) - int(ledger.data["queries"]))
        visited_key = sha256_text("|".join([qn, normalize_query(entity or ""), pins_for_key]))
        if conn.execute("SELECT 1 FROM task_visited WHERE task_id=? AND attempt_id=? AND visited_key=?",
                        (task["task_id"], st.attempt["attempt_id"], visited_key)).fetchone():
            raise TaskError("HOP_DUPLICATE", "this query/entity/source-version combination was already visited")
        try:
            allocation = ledger.allocate(st.now, queries_left)
        except TaskError:
            ledger.save(conn, task["task_id"], st.attempt["attempt_id"])
            raise
        ledger.save(conn, task["task_id"], st.attempt["attempt_id"])
        conn.execute("UPDATE task_operation SET response_json=? WHERE operation_id=?",
                     (canonical_json({"phase": "intent", "allocation": allocation}), st.op_id))
        return {"allocation": allocation, "hop_no": hop_no, "parent_hop_id": parent_id, "entity": entity,
                "visited_key": visited_key, "query_norm": qn, "roots": roots}

    def _do_search(self, ctx: SecurityContext, st: _Started, args: dict[str, Any], prep: dict[str, Any]) -> dict[str, Any]:
        assert self.search is not None
        outcome = self.search.search(ctx, prep["roots"], args["query"], prep["allocation"])
        self._fault("after_execute")
        task_id, attempt_id = st.task["task_id"], st.attempt["attempt_id"]
        with self.store.tx() as conn:
            task = self._require_live(conn, st)
            ledger = RetrievalLedger.load(conn, task_id, attempt_id)
            ledger.charge(outcome["consumed"])
            pins: dict[str, str] = ledger.data["pins"]
            existing = {(r[0], r[1]) for r in conn.execute(
                "SELECT block_instance_id, source_version_id FROM task_evidence WHERE task_id=? AND attempt_id=?",
                (task_id, attempt_id))}
            hop_id = new_id()
            now = self.clock()
            kept: list[dict[str, Any]] = []
            drifted = filtered = duplicates = 0
            for res in outcome["results"]:
                cit = res["citation"]
                fid, ver = res["file_record_id"], cit["source_version_id"]
                if not self.search.acl_ok(ctx, fid):
                    filtered += 1
                    continue
                if fid in pins and pins[fid] != ver:
                    drifted += 1
                    continue
                if (res["block_instance_id"], ver) in existing:
                    duplicates += 1
                    continue
                pins.setdefault(fid, ver)
                existing.add((res["block_instance_id"], ver))
                eid = new_id()
                conn.execute(
                    "INSERT INTO task_evidence(evidence_id, task_id, attempt_id, step_id, hop_id, file_record_id, "
                    "source_root_id, block_instance_id, source_version_id, citation_id, text, text_sha256, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (eid, task_id, attempt_id, st.step["step_id"], hop_id, fid, res["source_root_id"],
                     res["block_instance_id"], ver, cit["citation_id"], res["text"], sha256_text(res["text"]),
                     utc_iso(now)))
                kept.append({"evidence_id": eid, "file_record_id": fid, "source_version_id": ver,
                             "citation_id": cit["citation_id"], "score": res["score"], "text": res["text"]})
            if drifted:
                self._ev(conn, task_id, "version_drift", {"dropped": drifted}, attempt_id=attempt_id,
                         step_id=st.step["step_id"])
            if filtered:
                self._ev(conn, task_id, "acl_filtered", {"dropped": filtered}, attempt_id=attempt_id,
                         step_id=st.step["step_id"])
            rem = ledger.remaining(now)
            stop: str | None = None
            if not kept and drifted:
                stop = "version_drift"
            elif not kept and filtered:
                stop = "permission_denied"
            elif not kept:
                stop = "no_new_evidence"
            elif outcome["status"] == "timed_out":
                stop = "deadline"
            elif min(rem["elapsed_ms"], rem["candidates"], rem["opened_files"], rem["opened_blocks"],
                     rem["returned_bytes"], rem["queries"]) <= 0:
                stop = "budget_exhausted"
            elif st.step_def["kind"] == "multihop" and prep["hop_no"] >= int(
                    json.loads(task["params_json"]).get("max_hops", LIMITS["max_hops"])):
                stop = "hop_limit"
            conn.execute(
                "INSERT INTO task_hop(hop_id, task_id, attempt_id, step_id, parent_hop_id, hop_no, query_norm, entity, "
                "visited_key, status, stop_reason, evidence_count, consumed_json, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (hop_id, task_id, attempt_id, st.step["step_id"], prep["parent_hop_id"], prep["hop_no"],
                 prep["query_norm"], prep["entity"], prep["visited_key"], "completed", stop, len(kept),
                 canonical_json(outcome["consumed"]), utc_iso(now)))
            conn.execute("INSERT INTO task_visited(task_id, attempt_id, visited_key) VALUES (?,?,?)",
                         (task_id, attempt_id, prep["visited_key"]))
            if prep["parent_hop_id"]:
                ledger.data["branches"][prep["parent_hop_id"]] = int(
                    ledger.data["branches"].get(prep["parent_hop_id"], 0)) + 1
            ledger.save(conn, task_id, attempt_id)
            self._ev(conn, task_id, "hop_recorded",
                     {"hop_id": hop_id, "hop_no": prep["hop_no"], "parent_hop_id": prep["parent_hop_id"],
                      "evidence": len(kept), "duplicates": duplicates, "stop_reason": stop,
                      "consumed": outcome["consumed"], "receipt_ids": outcome["receipt_ids"],
                      "query_sha256": sha256_text(args["query"])},
                     attempt_id=attempt_id, step_id=st.step["step_id"])
            result = clip_response({
                "hop_id": hop_id, "hop_no": prep["hop_no"], "status": outcome["status"],
                "stop_reason": stop, "search_stop_reason": outcome["stop_reason"],
                "warning": outcome["warning"], "evidence": kept,
                "dropped": {"version_drift": drifted, "acl_filtered": filtered, "duplicates": duplicates},
            }, "evidence")
            self._finish_op(conn, st.op_id, "completed", result)
            return {"result": result, "envelope": self._envelope(conn, self.store.require_task(task_id, conn))}

    # ------------------------------------------------------------------ recall memory
    def _prep_recall(self, st: _Started) -> dict[str, Any]:
        if self.memory is None:
            raise TaskError("ACTION_NOT_ALLOWED", "memory backend unavailable")
        params = json.loads(st.task["params_json"])
        if "memory_scope_id" not in params:
            raise TaskError("ACTION_NOT_ALLOWED", "this task has no memory scope")
        return {"scope": params["memory_scope_id"]}

    def _do_recall(self, ctx: SecurityContext, st: _Started, args: dict[str, Any], prep: dict[str, Any]) -> dict[str, Any]:
        assert self.memory is not None
        recalled = self.memory.recall(ctx, prep["scope"], int(args.get("limit", 8)))
        self._fault("after_execute")
        task_id = st.task["task_id"]
        with self.store.tx() as conn:
            self._require_live(conn, st)
            result = clip_response({"items": recalled["items"], "receipt_id": recalled["receipt_id"]}, "items")
            self._ev(conn, task_id, "memory_recalled", {"count": len(result["items"]),
                                                         "receipt_id": recalled["receipt_id"]},
                     attempt_id=st.attempt["attempt_id"], step_id=st.step["step_id"])
            self._finish_op(conn, st.op_id, "completed", result)
            return {"result": result, "envelope": self._envelope(conn, self.store.require_task(task_id, conn))}

    def _do_published_recall(self, ctx: SecurityContext, st: _Started, args: dict[str, Any]) -> dict[str, Any]:
        from ..governed_recall import recall_governed_memory
        from ..validation import ContractError
        assert self.memory is not None
        limit = max(1, min(8, int(args.get("limit", 8))))
        try:
            recalled = recall_governed_memory(
                self.memory.catalog.conn,
                workspace_id=ctx.workspace_id,
                principal_id=ctx.principal_id,
                requested_layer="l2",
                query=str(args["query"]),
                result_limit=limit,
                query_id=str(uuid.uuid4()),
            )
        except ContractError as exc:
            raise TaskError("TASK_VALIDATION_ERROR", "published memory recall rejected") from exc
        self._fault("after_execute")
        items = [{
            "memory_id": item["metadata"]["target_id"],
            "content": item["content"],
            "layer": "l2",
            "approval": "published",
        } for item in recalled["results"]]
        task_id = st.task["task_id"]
        with self.store.tx() as conn:
            self._require_live(conn, st)
            result = clip_response(
                {"items": items, "receipt_id": recalled["receipt"]["receipt_id"], "layer": "l2"},
                "items",
            )
            self._ev(conn, task_id, "published_memory_recalled",
                     {"count": len(result["items"]), "receipt_id": result["receipt_id"]},
                     attempt_id=st.attempt["attempt_id"], step_id=st.step["step_id"])
            self._finish_op(conn, st.op_id, "completed", result)
            return {"result": result, "envelope": self._envelope(conn, self.store.require_task(task_id, conn))}

    # ------------------------------------------------------------------ write_candidate
    def _prep_write(self, conn: sqlite3.Connection, st: _Started, args: dict[str, Any]) -> dict[str, Any]:
        from .contracts import validate_candidate_name
        validate_candidate_name(args["name"])
        used = conn.execute("SELECT COALESCE(SUM(size_bytes),0) FROM task_artifact WHERE task_id=?",
                            (st.task["task_id"],)).fetchone()[0]
        return {"used": int(used)}

    def _do_write(self, st: _Started, args: dict[str, Any], prep: dict[str, Any]) -> dict[str, Any]:
        task_id, attempt_id = st.task["task_id"], st.attempt["attempt_id"]
        rel, sha, size = self.workspace.write_candidate(task_id, attempt_id, args["name"], args["content"],
                                                        used_bytes=prep["used"])
        data = self.workspace.read_candidate(rel, sha)
        sealed = self.engine.seal(task_id=task_id, attempt_id=attempt_id, name=args["name"], data=data, sha256=sha)
        self._fault("after_execute")
        with self.store.tx() as conn:
            self._require_live(conn, st)
            conn.execute(
                "INSERT INTO task_artifact(artifact_id, task_id, attempt_id, step_id, name, sha256, size_bytes, "
                "rel_path, origin, created_at) VALUES (?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(task_id, attempt_id, name) DO NOTHING",
                (new_id(), task_id, attempt_id, st.step["step_id"], args["name"], sha, size, rel, "engine",
                 utc_iso(self.clock())))
            self._ev(conn, task_id, "engine_run", {"run_id": sealed["run_id"], "status": sealed["engine_status"],
                                                   "manifest_sha256": sealed["manifest_sha256"]},
                     origin="engine", attempt_id=attempt_id, step_id=st.step["step_id"])
            self._ev(conn, task_id, "candidate_sealed", {"name": args["name"], "sha256": sha, "size": size},
                     attempt_id=attempt_id, step_id=st.step["step_id"])
            result = {"name": args["name"], "sha256": sha, "size_bytes": size,
                      "engine_status": sealed["engine_status"], "engine_review": sealed["engine_review"]}
            self._finish_op(conn, st.op_id, "completed", result)
            return {"result": result, "envelope": self._envelope(conn, self.store.require_task(task_id, conn))}

    # ------------------------------------------------------------------ submit_step
    def _prep_submit(self, conn: sqlite3.Connection, st: _Started, args: dict[str, Any]) -> dict[str, Any]:
        artifact = args["artifact"]
        incomplete = bool(args.get("declare_incomplete"))
        kind = st.step_def["kind"]
        template = get_template(st.task["template_id"])
        if incomplete:
            return {"incomplete": True, "reason": args.get("reason") or "missing_link", "verdict": None}
        if utf8_len(canonical_json(artifact)) > LIMITS["candidate_output_bytes"]:
            raise TaskError("TASK_RESULT_TOO_LARGE", "artifact too large")
        info: dict[str, Any] = {}
        if kind == "retrieval":
            vf.validate_selection(conn, st.task["task_id"], st.attempt["attempt_id"], artifact)
        elif kind == "multihop":
            info = vf.validate_trace(conn, st.task, st.attempt["attempt_id"], artifact)
        else:
            err = vf.schema_errors(template["final_artifact_schema"], artifact)
            if err:
                raise TaskError("RESULT_REJECTED", f"final artifact invalid: {err}")
        return {"incomplete": False, "info": info}

    def _do_submit(self, ctx: SecurityContext, st: _Started, args: dict[str, Any], prep: dict[str, Any]) -> dict[str, Any]:
        task_id, attempt_id, step_id = st.task["task_id"], st.attempt["attempt_id"], st.step["step_id"]
        artifact = args["artifact"]
        kind = st.step_def["kind"]
        sealed: dict[str, Any] | None = None
        seal_meta: dict[str, Any] | None = None
        if not prep["incomplete"] and kind == "final":
            body = canonical_json(artifact)
            with self.store.tx() as conn:
                used = conn.execute("SELECT COALESCE(SUM(size_bytes),0) FROM task_artifact WHERE task_id=?",
                                    (task_id,)).fetchone()[0]
            rel, sha, size = self.workspace.write_candidate(task_id, attempt_id, "result.json", body,
                                                            used_bytes=int(used))
            data = self.workspace.read_candidate(rel, sha)
            sealed = self.engine.seal(task_id=task_id, attempt_id=attempt_id, name="result.json", data=data,
                                      sha256=sha)
            seal_meta = {"rel": rel, "sha": sha, "size": size}
            self._fault("after_seal")
        with self.store.tx() as conn:
            task = self._require_live(conn, st)
            now = self.clock()
            artifact_json = canonical_json(artifact)
            digest = sha256_text(artifact_json)
            if prep["incomplete"]:
                reason = prep["reason"]
                conn.execute("UPDATE task_attempt SET state='rejected', incomplete=1, stop_reason=?, "
                             "artifact_json=?, artifact_sha256=?, ended_at=? WHERE attempt_id=?",
                             (reason, artifact_json, digest, utc_iso(now), attempt_id))
                target = WAITING_INPUT if reason == "needs_input" else NEEDS_REVIEW
                v = self.store.cas_state(conn, task_id, task["state_version"], target,
                                         reason=f"incomplete:{reason}", now=now)
                self._ev(conn, task_id, "step_incomplete", {"reason": reason, "evidence_complete": False},
                         attempt_id=attempt_id, step_id=step_id)
                self._ev(conn, task_id, "state_changed", {"from": RUNNING, "to": target, "state_version": v,
                                                          "reason": reason})
                conn.execute("UPDATE task_lease SET expires_at_epoch=0 WHERE task_id=?", (task_id,))
                result = {"accepted": False, "incomplete": True, "stop_reason": reason, "state": target}
            else:
                info = prep.get("info", {})
                if kind == "multihop" and info.get("ambiguous"):
                    conn.execute("UPDATE task_attempt SET state='rejected', incomplete=1, stop_reason=?, "
                                 "artifact_json=?, artifact_sha256=?, ended_at=? WHERE attempt_id=?",
                                 ("ambiguity_unresolved", artifact_json, digest, utc_iso(now), attempt_id))
                    v = self.store.cas_state(conn, task_id, task["state_version"], NEEDS_REVIEW,
                                             reason="incomplete:ambiguity_unresolved", now=now)
                    self._ev(conn, task_id, "step_incomplete", {"reason": "ambiguity_unresolved",
                                                                "evidence_complete": False},
                             attempt_id=attempt_id, step_id=step_id)
                    self._ev(conn, task_id, "state_changed", {"from": RUNNING, "to": NEEDS_REVIEW,
                                                              "state_version": v})
                    conn.execute("UPDATE task_lease SET expires_at_epoch=0 WHERE task_id=?", (task_id,))
                    result = {"accepted": False, "incomplete": True, "stop_reason": "ambiguity_unresolved",
                              "state": NEEDS_REVIEW}
                else:
                    result = self._accept_step(conn, task, st, artifact_json, digest, sealed, seal_meta, now)
            self._finish_op(conn, st.op_id, "completed", result)
            return {"result": result, "envelope": self._envelope(conn, self.store.require_task(task_id, conn))}

    def _accept_step(self, conn: sqlite3.Connection, task: sqlite3.Row, st: _Started, artifact_json: str,
                     digest: str, sealed: dict[str, Any] | None, seal_meta: dict[str, Any] | None,
                     now: float) -> dict[str, Any]:
        task_id, attempt_id, step_id = task["task_id"], st.attempt["attempt_id"], st.step["step_id"]
        conn.execute("UPDATE task_attempt SET state='accepted', artifact_json=?, artifact_sha256=?, ended_at=? "
                     "WHERE attempt_id=?", (artifact_json, digest, utc_iso(now), attempt_id))
        conn.execute("UPDATE task_step SET state='accepted' WHERE task_id=? AND step_id=?", (task_id, step_id))
        if sealed and seal_meta:
            conn.execute(
                "INSERT INTO task_artifact(artifact_id, task_id, attempt_id, step_id, name, sha256, size_bytes, "
                "rel_path, origin, created_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(task_id, attempt_id, name) "
                "DO NOTHING", (new_id(), task_id, attempt_id, step_id, "result.json", seal_meta["sha"],
                               seal_meta["size"], seal_meta["rel"], "engine", utc_iso(now)))
            self._ev(conn, task_id, "engine_run", {"run_id": sealed["run_id"], "status": sealed["engine_status"],
                                                   "manifest_sha256": sealed["manifest_sha256"],
                                                   "engine_review": sealed["engine_review"]},
                     origin="engine", attempt_id=attempt_id, step_id=step_id)
        self._ev(conn, task_id, "step_accepted", {"artifact_sha256": digest}, attempt_id=attempt_id, step_id=step_id)
        promoted = self._advance_steps(conn, self.store.require_task(task_id, conn), now)
        terminal = not any(step_id in s["depends_on"] for s in self._template_steps(task))
        result: dict[str, Any] = {"accepted": True, "artifact_sha256": digest, "next_steps": promoted}
        if not terminal:
            result["state"] = RUNNING
            return result
        v = self.store.cas_state(conn, task_id, task["state_version"], AWAITING_VERIFICATION, now=now)
        self._ev(conn, task_id, "state_changed", {"from": RUNNING, "to": AWAITING_VERIFICATION, "state_version": v})
        fresh = self.store.require_task(task_id, conn)
        final_attempt = conn.execute("SELECT * FROM task_attempt WHERE attempt_id=?", (attempt_id,)).fetchone()
        verdict = self._verify(conn, fresh, final_attempt)
        if sealed and sealed.get("engine_review") and verdict.outcome == "succeeded":
            # Engine ``completed_with_review`` is never task success; it forces human review.
            verdict = vf.Verdict("needs_review", "engine_completed_with_review",
                                 verdict.checks + [{"id": "engine_status", "status": "review",
                                                    "detail": "completed_with_review"}])
        state = self._apply_verdict(conn, fresh, verdict, now)
        result.update({"state": state, "verification": verdict.as_dict()})
        return result

    def _acl_checker(self, task: sqlite3.Row) -> Callable[[str], bool]:
        if self.search is None:
            return lambda _fid: True
        ctx = SecurityContext(workspace_id=task["workspace_id"], principal_id=task["principal_id"])
        return lambda fid: self.search.acl_ok(ctx, fid)

    def _verify(self, conn: sqlite3.Connection, task: sqlite3.Row, final_attempt: sqlite3.Row) -> vf.Verdict:
        step_def = next(s for s in self._template_steps(task) if s["id"] == final_attempt["step_id"])
        parents = accepted_parent_artifacts(conn, task["task_id"], step_def["depends_on"])
        recalled: set[str] = set()
        for p in parents:
            for r in conn.execute("SELECT response_json FROM task_operation WHERE task_id=? AND attempt_id=? "
                                  "AND action IN ('recall_memory', 'recall_published_memory') AND state='completed'",
                                  (task["task_id"], p["attempt_id"])):
                recalled.update(i["memory_id"] for i in json.loads(r[0]).get("items", []))
        return vf.verify_task(conn, task, final_attempt, parents=parents, recalled_memory_ids=recalled,
                              acl_check=self._acl_checker(task))

    def _apply_verdict(self, conn: sqlite3.Connection, task: sqlite3.Row, verdict: vf.Verdict, now: float) -> str:
        target = {"succeeded": SUCCEEDED, "needs_review": NEEDS_REVIEW, "failed": FAILED}[verdict.outcome]
        v = self.store.cas_state(conn, task["task_id"], task["state_version"], target,
                                 reason=verdict.reason[:200], now=now)
        self._ev(conn, task["task_id"], "verification", verdict.as_dict(), origin="verifier", terminal=True)
        self._ev(conn, task["task_id"], "state_changed", {"from": AWAITING_VERIFICATION, "to": target,
                                                          "state_version": v}, terminal=True)
        conn.execute("UPDATE task_lease SET expires_at_epoch=0 WHERE task_id=?", (task["task_id"],))
        if target == SUCCEEDED:
            self._maybe_enqueue_memory(conn, self.store.require_task(task["task_id"], conn), now)
        return target

    def _maybe_enqueue_memory(self, conn: sqlite3.Connection, task: sqlite3.Row, now: float) -> None:
        params = json.loads(task["params_json"])
        if not params.get("propose_memory"):
            return
        final = conn.execute(
            "SELECT a.artifact_json FROM task_attempt a JOIN task_step s ON s.current_attempt_id=a.attempt_id "
            "WHERE s.task_id=? AND s.step_id='produce'", (task["task_id"],)).fetchone()
        artifact = json.loads(final[0])
        cite = conn.execute("SELECT citation_id FROM task_evidence WHERE evidence_id=?",
                            (artifact["evidence_ids"][0],)).fetchone()
        payload = {"scope_id": params["memory_scope_id"], "content": canonical_json(artifact["output"])[:8000],
                   "citation_id": cite[0], "workspace_id": task["workspace_id"], "principal_id": task["principal_id"]}
        key = f"task-memory-{task['task_id']}"
        conn.execute("INSERT INTO task_outbox(outbox_id, task_id, kind, idempotency_key, payload_json, state, "
                     "attempts, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?) "
                     "ON CONFLICT(idempotency_key) DO NOTHING",
                     (new_id(), task["task_id"], "memory_proposal", key, canonical_json(payload), "pending", 0,
                      utc_iso(now), utc_iso(now)))
        self._ev(conn, task["task_id"], "outbox_enqueued", {"kind": "memory_proposal"}, terminal=True)

    # ------------------------------------------------------------------ cancel / resume / review
    def cancel_task(self, ctx: SecurityContext, task_id: str, reason: str | None = None) -> dict[str, Any]:
        now = self.clock()
        with self.store.tx() as conn:
            task = self.store.require_task(task_id, conn)
            authorize(ctx, "cancel_task", task["workspace_id"], task["principal_id"])
            check_transition(task["state"], CANCELLED)
            v = self.store.cas_state(conn, task_id, task["state_version"], CANCELLED,
                                     reason=(reason or "cancelled")[:200], now=now)
            self._ev(conn, task_id, "state_changed", {"from": task["state"], "to": CANCELLED, "state_version": v},
                     terminal=True)
            conn.execute("UPDATE task_lease SET expires_at_epoch=0 WHERE task_id=?", (task_id,))
            return self._summary(conn, self.store.require_task(task_id, conn))

    def _reauthorize(self, conn: sqlite3.Connection, ctx: SecurityContext, task: sqlite3.Row) -> None:
        appr = conn.execute("SELECT * FROM task_approval WHERE task_id=?", (task["task_id"],)).fetchone()
        if appr is None or appr["revoked_at"] is not None or appr["params_sha256"] != task["params_sha256"]:
            raise TaskError("TASK_AUTH_REVOKED", "task approval is missing, revoked or no longer matches")
        if self.search is not None:
            roots = json.loads(task["params_json"])["source_root_ids"]
            enabled = set(self.search.roots_enabled(ctx, roots))
            if any(r not in enabled for r in roots):
                raise TaskError("SOURCE_NOT_AUTHORIZED", "a task source root is no longer authorized")

    def resume_task(self, ctx: SecurityContext, task_id: str) -> dict[str, Any]:
        now = self.clock()
        with self.store.tx() as conn:
            task = self.store.require_task(task_id, conn)
            authorize(ctx, "resume_task", task["workspace_id"], task["principal_id"])
            if task["state"] not in (INTERRUPTED, WAITING_INPUT, RUNNING):
                check_transition(task["state"], RUNNING)  # raises with the right message
            self._reauthorize(conn, ctx, task)
            lease = conn.execute("SELECT * FROM task_lease WHERE task_id=?", (task_id,)).fetchone()
            if lease is not None and lease["owner_id"] != self.owner_id and lease["expires_at_epoch"] > now:
                raise TaskError("LEASE_HELD", "another executor holds the task lease")
            token = self.store.acquire_lease(conn, task_id, self.owner_id, allow_takeover=True)
            self._tokens[task_id] = token
            report = self._reconcile_operations(conn, task, now)
            deadline = float(task["deadline_epoch"])
            if task["state"] in (INTERRUPTED, WAITING_INPUT):
                deadline += max(0.0, now - float(task["last_seen_epoch"]))  # paused time is not consumed
                conn.execute("UPDATE task SET deadline_epoch=? WHERE task_id=?", (deadline, task_id))
            if now > deadline:
                v = self.store.cas_state(conn, task_id, task["state_version"], TIMED_OUT, reason="deadline", now=now)
                self._ev(conn, task_id, "state_changed", {"from": task["state"], "to": TIMED_OUT,
                                                          "state_version": v}, terminal=True)
                raise_after = TaskError("TASK_DEADLINE_EXCEEDED", "task wall-clock budget exhausted")
            else:
                raise_after = None
                if task["state"] != RUNNING:
                    v = self.store.cas_state(conn, task_id, task["state_version"], RUNNING, now=now)
                    self._ev(conn, task_id, "state_changed", {"from": task["state"], "to": RUNNING,
                                                              "state_version": v, "reconciled": report})
                self._ev(conn, task_id, "task_resumed", {"fencing_token": token, "reconciled": report})
            summary = self._summary(conn, self.store.require_task(task_id, conn))
        if raise_after is not None:
            raise raise_after
        return summary

    def _reconcile_operations(self, conn: sqlite3.Connection, task: sqlite3.Row, now: float) -> dict[str, int]:
        """Mark interrupted operations ``unknown``; charge conservative retrieval cost; no replay of effects."""
        counts = {"unknown_ops": 0, "charged_searches": 0}
        for op in conn.execute("SELECT * FROM task_operation WHERE task_id=? AND state='intent'",
                               (task["task_id"],)).fetchall():
            counts["unknown_ops"] += 1
            conn.execute("UPDATE task_operation SET state='unknown', updated_at=? WHERE operation_id=?",
                         (utc_iso(now), op["operation_id"]))
            if op["action"] == "search" and op["response_json"]:
                allocation = json.loads(op["response_json"]).get("allocation")
                if allocation and op["attempt_id"]:
                    ledger = RetrievalLedger.load(conn, task["task_id"], op["attempt_id"])
                    ledger.charge({k: v for k, v in allocation.items()})
                    ledger.save(conn, task["task_id"], op["attempt_id"])
                    counts["charged_searches"] += 1
        return counts

    def review_task_result(self, ctx: SecurityContext, task_id: str, decision: str, *, step_id: str | None = None,
                           note: str | None = None, expected_state_version: int | None = None) -> dict[str, Any]:
        if decision not in ("accept", "reject", "rework"):
            raise TaskError("TASK_VALIDATION_ERROR", "decision must be accept, reject or rework")
        now = self.clock()
        with self.store.tx() as conn:
            task = self.store.require_task(task_id, conn)
            authorize(ctx, "review_task_result", task["workspace_id"], None)
            if task["state"] != NEEDS_REVIEW:
                check_transition(task["state"], SUCCEEDED if decision == "accept" else FAILED)
                raise TaskError("TASK_INVALID_TRANSITION", "task is not awaiting review")
            if expected_state_version is not None and expected_state_version != task["state_version"]:
                raise TaskError("TASK_STATE_CONFLICT", "state_version mismatch")
            incomplete = conn.execute("SELECT 1 FROM task_attempt WHERE task_id=? AND incomplete=1 AND state='rejected' "
                                      "AND attempt_id IN (SELECT current_attempt_id FROM task_step WHERE task_id=?)",
                                      (task_id, task_id)).fetchone()
            self._ev(conn, task_id, "review_decision", {"decision": decision, "step_id": step_id,
                                                        "reviewer_kind": ctx.actor_kind,
                                                        "note": (note or "")[:500]}, origin="reviewer", terminal=True)
            if decision == "accept":
                if incomplete:
                    raise TaskError("RESULT_REJECTED", "an incomplete step cannot be accepted; rework or reject")
                final_ok = conn.execute(
                    "SELECT 1 FROM task_step WHERE task_id=? AND state!='accepted'", (task_id,)).fetchone()
                if final_ok:
                    raise TaskError("RESULT_REJECTED", "not every step is accepted; rework or reject")
                v = self.store.cas_state(conn, task_id, task["state_version"], SUCCEEDED, reason="review_accepted", now=now)
                self._ev(conn, task_id, "state_changed", {"from": NEEDS_REVIEW, "to": SUCCEEDED, "state_version": v},
                         terminal=True)
                self._maybe_enqueue_memory(conn, self.store.require_task(task_id, conn), now)
            elif decision == "reject":
                v = self.store.cas_state(conn, task_id, task["state_version"], FAILED, reason="review_rejected", now=now)
                self._ev(conn, task_id, "state_changed", {"from": NEEDS_REVIEW, "to": FAILED, "state_version": v},
                         terminal=True)
            else:
                self._rework(conn, task, step_id, note, now)
            summary = self._summary(conn, self.store.require_task(task_id, conn))
        self._after_commit(task_id)
        return summary

    def _descendants(self, task: sqlite3.Row, step_id: str) -> set[str]:
        steps = self._template_steps(task)
        out: set[str] = set()
        frontier = {step_id}
        while frontier:
            nxt = {s["id"] for s in steps if set(s["depends_on"]) & frontier} - out
            out |= nxt
            frontier = nxt
        return out

    def _rework(self, conn: sqlite3.Connection, task: sqlite3.Row, step_id: str | None, note: str | None,
                now: float) -> None:
        steps = {s["id"]: s for s in self._template_steps(task)}
        if step_id is None or step_id not in steps:
            raise TaskError("TASK_VALIDATION_ERROR", "rework requires a valid step_id")
        affected = {step_id} | self._descendants(task, step_id)
        preserved = sorted(set(steps) - affected)
        for sid in affected:
            row = conn.execute("SELECT current_attempt_id FROM task_step WHERE task_id=? AND step_id=?",
                               (task["task_id"], sid)).fetchone()
            if row["current_attempt_id"]:
                conn.execute("UPDATE task_attempt SET state='superseded', ended_at=COALESCE(ended_at, ?) "
                             "WHERE attempt_id=? AND state!='superseded'", (utc_iso(now), row["current_attempt_id"]))
            conn.execute("UPDATE task_step SET state='pending', current_attempt_id=NULL WHERE task_id=? AND step_id=?",
                         (task["task_id"], sid))
        # the reworked step restarts from its (preserved, digest-pinned) parents
        digests: dict[str, str] = {}
        for dep in steps[step_id]["depends_on"]:
            dep_row = conn.execute("SELECT current_attempt_id FROM task_step WHERE task_id=? AND step_id=?",
                                   (task["task_id"], dep)).fetchone()
            att = conn.execute("SELECT artifact_sha256 FROM task_attempt WHERE attempt_id=?",
                               (dep_row["current_attempt_id"],)).fetchone()
            digests[dep] = att["artifact_sha256"]
        self._new_attempt(conn, task, step_id, steps[step_id]["kind"], digests, now, note=(note or "")[:500] or None)
        deadline = float(task["deadline_epoch"]) + max(0.0, now - float(task["last_seen_epoch"]))
        conn.execute("UPDATE task SET deadline_epoch=? WHERE task_id=?", (deadline, task["task_id"]))
        v = self.store.cas_state(conn, task["task_id"], task["state_version"], RUNNING, reason=None, now=now)
        self._ev(conn, task["task_id"], "rework_started",
                 {"step_id": step_id, "reworked_steps": sorted(affected), "preserved_steps": preserved},
                 origin="reviewer")
        self._ev(conn, task["task_id"], "state_changed", {"from": NEEDS_REVIEW, "to": RUNNING, "state_version": v})

    # ------------------------------------------------------------------ lifecycle
    def recover(self) -> dict[str, Any]:
        from . import recovery
        return recovery.recover(self)

    def purge_expired(self, ctx: SecurityContext) -> dict[str, Any]:
        authorize(ctx, "purge_expired_tasks")
        from . import recovery
        return recovery.purge_expired(self)

    def shutdown(self, timeout_sec: float = 5.0) -> dict[str, Any]:
        with self._cond:
            self._shutting_down = True
            deadline = time.monotonic() + timeout_sec
            while self._inflight > 0 and time.monotonic() < deadline:
                self._cond.wait(timeout=0.05)
            clean = self._inflight == 0
        interrupted: list[str] = []
        now = self.clock()
        with self.store.tx() as conn:
            rows = conn.execute("SELECT t.task_id, t.state_version FROM task t JOIN task_lease l ON l.task_id=t.task_id "
                                "WHERE t.state='running' AND l.owner_id=?", (self.owner_id,)).fetchall()
            for r in rows:
                v = self.store.cas_state(conn, r["task_id"], r["state_version"], INTERRUPTED,
                                         reason="service_shutdown", now=now)
                self._ev(conn, r["task_id"], "state_changed", {"from": RUNNING, "to": INTERRUPTED,
                                                               "reason": "service_shutdown", "state_version": v},
                         terminal=True)
                conn.execute("UPDATE task_lease SET expires_at_epoch=0 WHERE task_id=?", (r["task_id"],))
                interrupted.append(r["task_id"])
        self.store.checkpoint()
        return {"clean": clean, "interrupted_tasks": interrupted, "inflight_remaining": self._inflight}
