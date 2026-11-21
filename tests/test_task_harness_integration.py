"""Task harness wiring: MCP JSON-RPC, trusted capabilities, CLI operator, installer maintenance."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from task_harness_support import ALICE, BOB, CORPUS, WORKSPACE, Env, FakeClock, agent_ctx, human_ctx, key

from pdx_local_ai.service.contracts import SecurityContext
from pdx_local_ai.service.mcp_server import MCP_TOOLS, McpServerHandler
from pdx_local_ai.service.stdio_transport import McpStdioTransport
from pdx_local_ai.tasks.mcp_tools import TASK_TOOL_NAMES
from pdx_local_ai.tasks.store import TaskStore, migrate_tasks_database

T1 = {"questions": [{"field": "opener", "question": "Who opened session Orion-7?"}]}


class _Rpc:
    """Minimal scripted agent speaking JSON-RPC to the real transport object."""

    def __init__(self, env: Env, ctx: SecurityContext) -> None:
        self.handler = McpServerHandler(env.agent, ctx, task_service_factory=lambda: env.tasks)
        self.transport = McpStdioTransport(self.handler, stdin=io.StringIO(), stdout=io.StringIO(), stderr=io.StringIO())
        self._id = 0
        self.call("initialize", {"protocolVersion": "2024-11-05"})
        self.transport.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        return self.transport.handle_message({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})

    def tool(self, name: str, **arguments):
        resp = self.call("tools/call", {"name": name, "arguments": arguments})
        result = resp["result"]
        text = result["content"][0]["text"]
        return (json.loads(text) if not result["isError"] else text), result["isError"]


class McpWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(files=CORPUS, clock=FakeClock(time.time()))
        self.params = {"source_root_ids": [self.env.root_id], **T1}

    def tearDown(self) -> None:
        self.env.close()

    def test_tool_visibility_is_capability_gated_and_base_tools_unchanged(self) -> None:
        base = {t["name"] for t in MCP_TOOLS}
        agent = _Rpc(self.env, agent_ctx())
        names = {t["name"] for t in agent.call("tools/list")["result"]["tools"]}
        self.assertTrue(base < names)
        self.assertNotIn("approve_task", names)
        self.assertNotIn("review_task_result", names)
        self.assertTrue(TASK_TOOL_NAMES - {"approve_task", "review_task_result"} <= names)
        approver = _Rpc(self.env, agent_ctx(can_approve_tasks=True, can_review_tasks=True))
        names2 = {t["name"] for t in approver.call("tools/list")["result"]["tools"]}
        self.assertTrue({"approve_task", "review_task_result"} <= names2)
        no_tasks = McpServerHandler(self.env.agent, agent_ctx())  # no factory: surface identical to before
        self.assertEqual([t["name"] for t in no_tasks.list_tools()], [t["name"] for t in MCP_TOOLS])
        self.assertIsNone(no_tasks.close_tasks())

    def test_agent_cannot_approve_even_by_calling_the_hidden_tool(self) -> None:
        agent = _Rpc(self.env, agent_ctx())
        created, err = agent.tool("create_task", template_id="doc_evidence_check", params=self.params)
        self.assertFalse(err)
        self.assertEqual(created["state"], "awaiting_approval")
        for tool in ("approve_task", "review_task_result"):
            out, is_err = agent.tool(tool, task_id=created["task_id"], decision="accept")
            self.assertTrue(is_err, out)
            self.assertIn("TASK_PERMISSION_DENIED", out)
        _, is_err = agent.tool("dispatch_task_action", task_id=created["task_id"], action="search",
                               arguments={"query": "Orion-7"}, idempotency_key=key())
        self.assertTrue(is_err)  # not approved -> cannot run

    def test_self_approval_is_denied_even_with_capability_but_different_principal_is_hidden(self) -> None:
        both = _Rpc(self.env, agent_ctx(can_approve_tasks=True, actor_kind="agent"))
        created, _ = both.tool("create_task", template_id="doc_evidence_check", params=self.params)
        out, is_err = both.tool("approve_task", task_id=created["task_id"])
        self.assertTrue(is_err)
        self.assertIn("SELF_APPROVAL_DENIED", out)
        bob = _Rpc(self.env, agent_ctx(principal=BOB))
        out, is_err = bob.tool("get_task", task_id=created["task_id"])
        self.assertTrue(is_err)
        self.assertIn("TASK_NOT_FOUND", out)  # existence is not disclosed across principals
        other_ws = _Rpc(self.env, agent_ctx(workspace="00000000-0000-0000-0000-0000000000bb"))
        out, is_err = other_ws.tool("get_task", task_id=created["task_id"])
        self.assertIn("TASK_NOT_FOUND", out)

    def test_scripted_agent_completes_task_over_json_rpc_with_cli_approval(self) -> None:
        from pdx_local_ai.cli.main import main as cli_main
        env = self.env
        (env.profile / "config.json").write_text(json.dumps({"workspace_id": WORKSPACE, "default_principal_id": ALICE}),
                                                 encoding="utf-8")
        agent = _Rpc(env, agent_ctx())
        tpls, _ = agent.tool("list_task_templates")
        self.assertEqual({t["template_id"] for t in tpls["templates"]},
                         {"doc_evidence_check", "multihop_trace", "doc_memory_artifact"})
        created, _ = agent.tool("create_task", template_id="doc_evidence_check", params=self.params)
        tid = created["task_id"]
        out, buf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(buf):
            rc = cli_main(["task", "approve", tid, "--profile-dir", str(env.profile)])
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertEqual(json.loads(out.getvalue())["state"], "queued")
        s1, _ = agent.tool("dispatch_task_action", task_id=tid, action="search",
                           arguments={"query": "Session Orion-7 opened by"}, idempotency_key=key())
        self.assertEqual(s1["envelope"]["step_id"], "gather")  # envelope tells the agent what to do next
        self.assertIn("search", s1["envelope"]["available_actions"])
        self.assertIn("search", s1["envelope"]["action_schemas"])
        eid = next(e["evidence_id"] for e in s1["result"]["evidence"] if "Orion-7" in e["text"])
        key_g, key_r = key(), key()
        agent.tool("submit_task_result", task_id=tid, step_id="gather",
                   artifact={"selected_evidence_ids": [eid]}, idempotency_key=key_g)
        art = {"items": [{"field": "opener", "value": "Maria Lopez", "evidence_ids": [eid]}]}
        done, err = agent.tool("submit_task_result", task_id=tid, step_id="report", artifact=art, idempotency_key=key_r)
        self.assertFalse(err, done)
        self.assertEqual(done["result"]["state"], "succeeded")
        replay, _ = agent.tool("submit_task_result", task_id=tid, step_id="report", artifact=art, idempotency_key=key_r)
        self.assertTrue(replay["replayed"])
        # operator CLI list/show/events work on the same profile
        for argv in (["task", "list"], ["task", "show", tid], ["task", "events", tid]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli_main(argv + ["--profile-dir", str(env.profile)]), 0)
            self.assertTrue(json.loads(out.getvalue()))

    def test_every_response_and_event_stays_under_size_bounds(self) -> None:
        agent = _Rpc(self.env, agent_ctx())
        created, _ = agent.tool("create_task", template_id="doc_evidence_check", params=self.params)
        self.env.tasks.approve_task(human_ctx(), created["task_id"])
        resp = agent.call("tools/call", {"name": "dispatch_task_action", "arguments": {
            "task_id": created["task_id"], "action": "search", "arguments": {"query": "Orion-7 opened"},
            "idempotency_key": key()}})
        self.assertLessEqual(len(resp["result"]["content"][0]["text"].encode()), 64 * 1024 + 4096)
        ctx, _ = agent.tool("get_task_context", task_id=created["task_id"])
        self.assertLessEqual(ctx["context_bytes"], 64 * 1024)
        self.assertEqual(agent.transport.stdout.getvalue(), "")  # nothing leaks onto the protocol stream

    def test_handler_close_tasks_runs_task_shutdown(self) -> None:
        agent = _Rpc(self.env, agent_ctx())
        agent.tool("list_task_templates")
        summary = agent.handler.close_tasks(timeout_sec=1.0)
        self.assertTrue(summary["clean"])


class CliOperatorTests(unittest.TestCase):
    def test_cli_without_task_db_is_a_noop_and_missing_identity_is_an_error(self) -> None:
        from pdx_local_ai.cli.main import main as cli_main
        tmp = Path(tempfile.mkdtemp())
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(cli_main(["task", "list", "--profile-dir", str(tmp)]), 1)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cli_main(["task", "list", "--profile-dir", str(tmp), "--workspace-id", WORKSPACE,
                               "--principal-id", ALICE])
            self.assertEqual(rc, 0)
            self.assertFalse((tmp / "tasks.sqlite").exists())  # CLI never creates the task DB
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cli_review_and_cancel(self) -> None:
        from pdx_local_ai.cli.main import main as cli_main
        env = Env(files=CORPUS, clock=FakeClock(time.time()))
        try:
            task_id = env.create("doc_evidence_check", {"source_root_ids": [env.root_id], **T1})
            base = ["--profile-dir", str(env.profile), "--workspace-id", WORKSPACE, "--principal-id", ALICE]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli_main(["task", "cancel", task_id, "--reason", "no longer needed"] + base), 0)
            self.assertEqual(env.tasks.get_task(agent_ctx(), task_id)["state"], "cancelled")
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = cli_main(["task", "review", task_id, "--decision", "accept"] + base)
            self.assertEqual(rc, 1)
            self.assertIn("TASK_", err.getvalue())
        finally:
            env.close()


class InstallerMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.target, self.profile = self.root / "install", self.root / "profile"

    def _dist(self, name: str, payload: bytes) -> Path:
        from pdx_local_ai.windows_runtime_terms import terms_path
        dist = self.root / name
        (dist / "_internal" / "windows-runtime").mkdir(parents=True)
        (dist / "pdx-local.exe").write_bytes(payload)
        shutil.copy(terms_path(), dist / "_internal" / "windows-runtime" / "WINDOWS-RUNTIME-TERMS.txt")
        (dist / "_internal" / "windows-runtime" / "THIRD-PARTY-NOTICES.txt").write_text("notices", encoding="utf-8")
        return dist

    def _tasks_db(self) -> None:
        self.profile.mkdir(parents=True, exist_ok=True)
        migrate_tasks_database(self.profile / "tasks.sqlite")
        st = TaskStore(self.profile / "tasks.sqlite")
        with st.tx() as conn:
            conn.execute("INSERT INTO task(task_id, workspace_id, principal_id, creator_actor_kind, template_id,"
                         "template_version, template_sha256, context_mode, params_json, params_sha256, state,"
                         "state_version, created_at, updated_at, last_seen_epoch, deadline_epoch, input_bytes) "
                         "VALUES ('vital','w','p','agent','x','1','s','bounded_retrieval','{}','h','succeeded',3,'c','u',"
                         "1,2,2)")
        st.close()

    def _install(self, dist: Path, version: str):
        from pdx_local_ai.installer import Installer
        return Installer(self.target, self.profile).install(dist, version=version, accept_windows_runtime_terms=True)

    def test_upgrade_backs_up_and_migrates_tasks_database(self) -> None:
        ok, msg = self._install(self._dist("d1", b"OLD"), "0.0.1")
        self.assertTrue(ok, msg)
        self._tasks_db()
        ok, msg = self._install(self._dist("d2", b"NEW"), "0.0.2")
        self.assertTrue(ok, msg)
        backups = list((self.profile / "backups").glob("tasks_backup_pre_upgrade_*.sqlite"))
        self.assertEqual(len(backups), 1)
        for db in (backups[0], self.profile / "tasks.sqlite"):
            conn = sqlite3.connect(db)
            self.assertEqual(conn.execute("SELECT task_id FROM task").fetchone()[0], "vital")
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)
            conn.close()
        self.assertEqual((self.target / "pdx-local.exe").read_bytes(), b"NEW")

    def test_tasks_migration_failure_uses_existing_rollback_and_marker(self) -> None:
        ok, msg = self._install(self._dist("d1", b"OLD"), "0.0.1")
        self.assertTrue(ok, msg)
        self._tasks_db()
        with patch("pdx_local_ai.tasks.store.migrate_tasks_database", side_effect=RuntimeError("task migration boom")):
            ok, msg = self._install(self._dist("d2", b"NEW"), "0.0.2")
        self.assertFalse(ok)
        self.assertIn("migration", msg.lower())
        marker = json.loads((self.profile / "MIGRATION_FAILED").read_text(encoding="utf-8"))
        self.assertIn("task migration boom", marker["reason"])
        self.assertEqual((self.target / "pdx-local.exe").read_bytes(), b"OLD")  # old binaries restored
        conn = sqlite3.connect(self.profile / "tasks.sqlite")
        self.assertEqual(conn.execute("SELECT task_id FROM task").fetchone()[0], "vital")
        conn.close()
        self.assertEqual(len(list((self.profile / "backups").glob("tasks_backup_pre_upgrade_*.sqlite"))), 1)

    def test_newer_task_db_blocks_upgrade_instead_of_downgrading(self) -> None:
        ok, msg = self._install(self._dist("d1", b"OLD"), "0.0.1")
        self.assertTrue(ok, msg)
        self._tasks_db()
        conn = sqlite3.connect(self.profile / "tasks.sqlite")
        conn.execute("PRAGMA user_version=9")
        conn.close()
        ok, msg = self._install(self._dist("d2", b"NEW"), "0.0.2")
        self.assertFalse(ok)
        self.assertTrue((self.profile / "MIGRATION_FAILED").exists())
        conn = sqlite3.connect(self.profile / "tasks.sqlite")
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 9)  # untouched
        conn.close()

    def test_cli_purge_removes_task_database_and_workspaces(self) -> None:
        from pdx_local_ai.cli.main import main as cli_main
        profile = self.root / "p2"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli_main(["init", "--profile-dir", str(profile), "--workspace-id", WORKSPACE,
                                       "--principal-id", ALICE]), 0)
        migrate_tasks_database(profile / "tasks.sqlite")
        (profile / "tasks" / "11111111-1111-1111-1111-111111111111").mkdir(parents=True)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli_main(["purge", "--profile-dir", str(profile)]), 0)
        self.assertFalse(profile.exists())


_ = json

if __name__ == "__main__":
    unittest.main()
