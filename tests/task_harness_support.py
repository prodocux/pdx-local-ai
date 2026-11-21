"""Shared fixtures for task harness tests (not collected as tests)."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_SRC = _HERE.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pdx_local_ai.catalog import Catalog  # noqa: E402
from pdx_local_ai.service.agent_service import PdxLocalAgentService  # noqa: E402
from pdx_local_ai.service.contracts import SecurityContext  # noqa: E402
from pdx_local_ai.tasks.service import TaskService  # noqa: E402

WORKSPACE = "00000000-0000-0000-0000-0000000000aa"
ALICE = "alice"
BOB = "bob"


def extractor(name: str, payload: bytes) -> dict[str, Any]:
    return {
        "kernel_version": "test-v1", "truncated": False,
        "text_items": [{"text": payload.decode("utf-8"), "type": "text", "id": "k-0"}],
        "source_sha256": hashlib.sha256(payload).hexdigest(),
    }


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def agent_ctx(principal: str = ALICE, workspace: str = WORKSPACE, **kw: Any) -> SecurityContext:
    return SecurityContext(workspace_id=workspace, principal_id=principal, **kw)


def human_ctx(principal: str = ALICE, workspace: str = WORKSPACE, **kw: Any) -> SecurityContext:
    return SecurityContext(workspace_id=workspace, principal_id=principal, is_admin=True,
                           can_approve_tasks=True, can_review_tasks=True, actor_kind="human_cli", **kw)


def key() -> str:
    return "idem-" + uuid.uuid4().hex


class Env:
    """Temp profile with catalog, source root, agent service and TaskService."""

    def __init__(self, *, files: dict[str, str] | None = None, clock: FakeClock | None = None,
                 fault_hook: Any = None) -> None:
        self.dir = Path(tempfile.mkdtemp()).resolve()
        self.profile = self.dir / "profile"
        self.profile.mkdir()
        self.clock = clock or FakeClock()
        self.catalog = Catalog(self.profile / "catalog.sqlite", extractor=extractor)
        self.root_dir = self.dir / "src"
        self.root_dir.mkdir()
        self.root_id = self.catalog.add_root(workspace_id=WORKSPACE, canonical_path=str(self.root_dir))
        self.file_ids: dict[str, str] = {}
        for name, text in (files or {}).items():
            self.add_file(name, text)
        self.agent = PdxLocalAgentService(self.catalog)
        self.fault_hook = fault_hook
        self.tasks = TaskService.open(self.profile, agent_service=self.agent, clock=self.clock,
                                      fault_hook=lambda p: self.fault_hook(p) if self.fault_hook else None)

    # ------------------------------------------------------------ corpus
    def add_file(self, name: str, text: str, principal: str = ALICE) -> str:
        (self.root_dir / name).write_text(text, encoding="utf-8")
        self.catalog.scan(source_root_id=self.root_id, raise_on_error=False)
        row = self.catalog.conn.execute(
            "SELECT file_record_id FROM file_record WHERE workspace_id=? AND source_root_id=? AND relative_path=?",
            (WORKSPACE, self.root_id, name)).fetchone()
        fid = str(row[0])
        self.catalog.grant_read_access(workspace_id=WORKSPACE, principal_id=principal, file_record_id=fid)
        self.file_ids[name] = fid
        return fid

    def rewrite(self, name: str, text: str) -> None:
        (self.root_dir / name).write_text(text, encoding="utf-8")
        self.catalog.scan(source_root_id=self.root_id, raise_on_error=False)

    def revoke(self, name: str, principal: str = ALICE) -> None:
        self.catalog.conn.execute("UPDATE file_acl SET can_read=0 WHERE file_record_id=? AND principal_id=?",
                                  (self.file_ids[name], principal))
        self.catalog.conn.commit()

    # ------------------------------------------------------------ service helpers
    def new_service(self, *, clock: FakeClock | None = None, fault_hook: Any = None,
                    run_recovery: bool = False) -> TaskService:
        return TaskService.open(self.profile, agent_service=self.agent, clock=clock or self.clock,
                                fault_hook=fault_hook, run_recovery=run_recovery)

    def create(self, template: str, params: dict[str, Any], **kw: Any) -> str:
        out = self.tasks.create_task(agent_ctx(), template, params, **kw)
        return out["task_id"]

    def approved(self, template: str, params: dict[str, Any], **kw: Any) -> str:
        task_id = self.create(template, params, **kw)
        self.tasks.approve_task(human_ctx(), task_id)
        return task_id

    def act(self, task_id: str, action: str, args: dict[str, Any] | None = None, *, ctx: Any = None,
            service: TaskService | None = None) -> dict[str, Any]:
        return (service or self.tasks).dispatch_task_action(ctx or agent_ctx(), task_id, action, args or {}, key())

    def submit(self, task_id: str, step_id: str, artifact: dict[str, Any], **kw: Any) -> dict[str, Any]:
        return self.tasks.submit_task_result(agent_ctx(), task_id, step_id, artifact, key(), **kw)

    def close(self) -> None:
        try:
            self.tasks.store.close()
        except Exception:
            pass
        try:
            self.agent.worker.shutdown(timeout_sec=2.0)
        except Exception:
            pass
        try:
            self.catalog.conn.close()
        except Exception:
            pass
        shutil.rmtree(self.dir, ignore_errors=True)


def evidence_with(result: dict[str, Any], needle: str) -> str:
    for ev in result["result"]["evidence"]:
        if needle.lower() in ev["text"].lower():
            return ev["evidence_id"]
    raise AssertionError(f"no evidence containing {needle!r}: {[e['text'] for e in result['result']['evidence']]}")


CORPUS = {
    "a.txt": "Session Orion-7 was opened by Maria Lopez on the east cluster.",
    "b.txt": "Maria Lopez owns vault key KEY-4242 for the release train.",
    "c.txt": "Session Vega-2 was opened by Peter Chen on the west cluster.",
    "d.txt": "Peter Chen owns vault key KEY-9001 for the audit train.",
    "e.txt": "The cafeteria menu lists soup and bread on Tuesday.",
}

_MARKER = re.compile(r"\[\[(next|answer) ([A-Za-z0-9]+)\]\]")


def _ordered_hops(packet: dict[str, Any]) -> list[dict[str, Any]]:
    hops = list(packet["volatile"]["hops"])
    children: dict[str, list[dict[str, Any]]] = {}
    roots: list[dict[str, Any]] = []
    for hop in hops:
        parent = hop["parent_hop_id"]
        if parent is None:
            roots.append(hop)
        else:
            children.setdefault(parent, []).append(hop)
    ordered: list[dict[str, Any]] = []
    current = roots[0] if roots else None
    while current is not None:
        ordered.append(current)
        kids = children.get(current["hop_id"], [])
        current = kids[0] if kids else None
    return ordered


def _windows(packet: dict[str, Any], hop_id: str) -> list[dict[str, Any]]:
    return [item for item in packet["volatile"]["evidence_windows"] if item["hop_id"] == hop_id]


def _marker(text: str, kind: str) -> str | None:
    for found, value in _MARKER.findall(text):
        if found == kind:
            return value
    return None


def _search_arguments(packet: dict[str, Any]) -> dict[str, Any]:
    ordered = _ordered_hops(packet)
    if not ordered:
        return {"query": packet["prefix"]["params"]["start_entity"]}
    parent = ordered[-1]
    text = " ".join(item["text"] for item in _windows(packet, parent["hop_id"]))
    entity = _marker(text, "next")
    if entity is None:
        raise RuntimeError("packet window has no next-entity marker")
    return {"query": entity, "parent_hop_id": parent["hop_id"], "entity": entity}


def _trace_needs_search(packet: dict[str, Any]) -> bool:
    ordered = _ordered_hops(packet)
    if not ordered:
        return True
    text = " ".join(item["text"] for item in _windows(packet, ordered[-1]["hop_id"]))
    return _marker(text, "answer") is None


def _trace_artifact(packet: dict[str, Any]) -> dict[str, Any]:
    entity = packet["prefix"]["params"]["start_entity"]
    chain: list[dict[str, Any]] = []
    last_text = ""
    for hop in _ordered_hops(packet):
        chosen = next(item for item in _windows(packet, hop["hop_id"]) if entity.lower() in item["text"].lower())
        chain.append({"hop_id": hop["hop_id"], "entity": entity, "evidence_ids": [chosen["evidence_id"]]})
        last_text = chosen["text"]
        nxt = _marker(chosen["text"], "next")
        if nxt is not None:
            entity = nxt
    answer = _marker(last_text, "answer")
    if answer is None:
        raise RuntimeError("packet window has no answer marker")
    return {"chain": chain, "answer": answer}


def _report_artifact(packet: dict[str, Any]) -> dict[str, Any]:
    parent = next(item for item in packet["volatile"]["parents"] if item["step_id"] == "trace")
    return {"answer": parent["artifact"]["answer"], "trace_sha256": parent["artifact_sha256"]}


def scripted_multihop_driver(service: TaskService, ctx: Any, task_id: str) -> None:
    """Walk multihop_trace from the host packet and action list. No source files and no model."""
    for _ in range(8):
        view = service.get_task(ctx, task_id)
        if view["state"] == "succeeded":
            return
        if view["state"] not in ("queued", "running"):
            raise RuntimeError(view["state"])
        packet = service.get_task_context(ctx, task_id)
        actions = view["envelope"]["available_actions"]
        step_id = packet["prefix"]["step"]["id"]
        if step_id == "trace" and "search" in actions and _trace_needs_search(packet):
            service.dispatch_task_action(ctx, task_id, "search", _search_arguments(packet), key())
            continue
        if "submit_step" in actions and step_id == "trace":
            service.submit_task_result(ctx, task_id, step_id, _trace_artifact(packet), key())
            continue
        if "submit_step" in actions and step_id == "report":
            service.submit_task_result(ctx, task_id, step_id, _report_artifact(packet), key())
            continue
        raise RuntimeError(f"no scripted action for {step_id}")
    raise RuntimeError("scripted driver exceeded its step budget")


_ = json
