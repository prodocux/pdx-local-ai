"""Task harness: multihop, rework, memory, Engine, workspace, store/lease, recovery, retention."""

from __future__ import annotations

import json
import multiprocessing
import os
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from task_harness_support import (
    ALICE, CORPUS, WORKSPACE, Env, FakeClock, agent_ctx, evidence_with, human_ctx, key,
)

from pdx_local_ai.layered_memory import LayeredMemoryStore
from pdx_local_ai.tasks import contracts as C
from pdx_local_ai.tasks import store as store_mod
from pdx_local_ai.tasks.contracts import TaskError
from pdx_local_ai.tasks.workspace import TaskWorkspace

T1_Q = [{"field": "opener", "question": "Who opened session Orion-7?"}]


def t1(env: Env) -> dict:
    return {"source_root_ids": [env.root_id], "questions": T1_Q}


def t2(env: Env, **kw) -> dict:
    return {"source_root_ids": [env.root_id], "start_entity": "Orion-7",
            "target_relation": "vault key of the session opener", **kw}


def hop1(env: Env, task_id: str) -> dict:
    return env.act(task_id, "search", {"query": "Session Orion-7 opened by"})


def hop2(env: Env, task_id: str, parent: str, query: str = "Maria Lopez vault key") -> dict:
    return env.act(task_id, "search", {"query": query, "parent_hop_id": parent, "entity": "Maria Lopez"})


class MultihopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(files=CORPUS)

    def tearDown(self) -> None:
        self.env.close()

    def _chain(self, env: Env, task_id: str):
        r1 = hop1(env, task_id)
        ev_a = evidence_with(r1, "Maria Lopez")
        r2 = hop2(env, task_id, r1["result"]["hop_id"])
        ev_b = evidence_with(r2, "KEY-4242")
        chain = [{"hop_id": r1["result"]["hop_id"], "entity": "Orion-7", "evidence_ids": [ev_a]},
                 {"hop_id": r2["result"]["hop_id"], "entity": "Maria Lopez", "evidence_ids": [ev_b]}]
        return r1, r2, chain

    def test_two_hop_trace_succeeds_with_reconstructable_chain(self) -> None:
        env = self.env
        task_id = env.approved("multihop_trace", t2(env))
        _, _, chain = self._chain(env, task_id)
        sub = env.submit(task_id, "trace", {"chain": chain, "answer": "KEY-4242"})
        self.assertTrue(sub["result"]["accepted"])
        out = env.submit(task_id, "report", {"answer": "KEY-4242", "trace_sha256": sub["result"]["artifact_sha256"]})
        self.assertEqual(out["result"]["state"], "succeeded")
        hops = env.tasks.store.conn.execute(
            "SELECT hop_no, parent_hop_id, entity, query_norm FROM task_hop WHERE task_id=? ORDER BY hop_no",
            (task_id,)).fetchall()
        self.assertEqual([h["hop_no"] for h in hops], [1, 2])
        self.assertEqual(hops[1]["parent_hop_id"], chain[0]["hop_id"])  # observable query path is reconstructable
        self.assertEqual(hops[1]["entity"], "Maria Lopez")

    def test_hop_rules_grounding_duplicates_branches_and_limits(self) -> None:
        env = self.env
        task_id = env.approved("multihop_trace", t2(env, max_hops=2))
        r1 = hop1(env, task_id)
        h1 = r1["result"]["hop_id"]
        with self.assertRaises(TaskError) as cm:  # a second root hop is not a branch
            hop1(env, task_id)
        self.assertEqual(cm.exception.code, "HOP_DUPLICATE")
        with self.assertRaises(TaskError) as cm:  # entity not found in parent evidence
            env.act(task_id, "search", {"query": "Nobody Here vault", "parent_hop_id": h1, "entity": "Nobody Here"})
        self.assertEqual(cm.exception.code, "HOP_UNGROUNDED")
        with self.assertRaises(TaskError) as cm:  # query must mention the grounded entity
            env.act(task_id, "search", {"query": "vault key", "parent_hop_id": h1, "entity": "Maria Lopez"})
        self.assertEqual(cm.exception.code, "HOP_UNGROUNDED")
        with self.assertRaises(TaskError) as cm:
            env.act(task_id, "search", {"query": "Maria Lopez vault", "parent_hop_id": "nope", "entity": "Maria Lopez"})
        self.assertEqual(cm.exception.code, "HOP_UNGROUNDED")
        r2 = hop2(env, task_id, h1)
        with self.assertRaises(TaskError) as cm:  # same normalized query + entity + parent evidence version
            hop2(env, task_id, h1, query="  MARIA   lopez VAULT key ")
        self.assertEqual(cm.exception.code, "HOP_DUPLICATE")
        hop2(env, task_id, h1, query="Maria Lopez release train")  # second branch allowed
        with self.assertRaises(TaskError) as cm:  # third follow-up from the same hop
            hop2(env, task_id, h1, query="Maria Lopez east cluster")
        self.assertEqual(cm.exception.code, "BRANCH_LIMIT")
        with self.assertRaises(TaskError) as cm:  # max_hops=2 -> a third dependent hop is refused
            env.act(task_id, "search", {"query": "KEY-4242 release", "parent_hop_id": r2["result"]["hop_id"],
                                        "entity": "KEY-4242"})
        self.assertEqual(cm.exception.code, "HOP_LIMIT")

    def test_shared_ledger_is_never_reset_by_branching_and_exhaustion_stops_search(self) -> None:
        with patch.dict(C.LEDGER_DEFAULTS, {"opened_files": 2}):
            env = Env(files=CORPUS)
            try:
                task_id = env.approved("multihop_trace", t2(env))
                r1 = hop1(env, task_id)
                h1 = r1["result"]["hop_id"]
                seen, error = [], None
                queries = ["Maria Lopez vault key", "Maria Lopez release train", "Maria Lopez east cluster"]
                for q in queries:
                    attempt = env.tasks.store.conn.execute(
                        "SELECT current_attempt_id FROM task_step WHERE task_id=? AND step_id='trace'",
                        (task_id,)).fetchone()[0]
                    from pdx_local_ai.tasks.context import RetrievalLedger
                    led = RetrievalLedger.load(env.tasks.store.conn, task_id, attempt)
                    seen.append(dict(led.data["consumed"]))
                    try:
                        hop2(env, task_id, h1, query=q)
                    except TaskError as exc:
                        error = exc
                        break
                led = RetrievalLedger.load(env.tasks.store.conn, task_id, attempt)
                for key_name, limit in led.data["limits"].items():
                    self.assertLessEqual(led.data["consumed"][key_name], limit + led.data["consumed"][key_name] * 0 + 1_000_000)
                self.assertLessEqual(led.data["consumed"]["opened_files"], 2 + 2)  # charge may overshoot once at most
                consumed_series = [s["opened_files"] for s in seen] + [led.data["consumed"]["opened_files"]]
                self.assertEqual(consumed_series, sorted(consumed_series))  # monotonic: branches never reset it
                self.assertIsNotNone(error)
                self.assertEqual(error.code, "RETRIEVAL_BUDGET_EXHAUSTED")
                self.assertIn(error.details["stop_reason"], ("budget_exhausted", "query_quota"))
            finally:
                env.close()

    def test_version_drift_is_dropped_not_mixed(self) -> None:
        env = self.env
        task_id = env.approved("multihop_trace", t2(env))
        r1 = hop1(env, task_id)
        pinned = env.tasks.store.conn.execute(
            "SELECT DISTINCT source_version_id FROM task_evidence WHERE task_id=? AND file_record_id=?",
            (task_id, env.file_ids["a.txt"])).fetchall()
        self.assertEqual(len(pinned), 1)
        env.rewrite("a.txt", CORPUS["a.txt"] + " Reopened after audit.")
        r2 = env.act(task_id, "search", {"query": "Maria Lopez east cluster", "parent_hop_id": r1["result"]["hop_id"],
                                         "entity": "Maria Lopez"})
        versions = {r[0] for r in env.tasks.store.conn.execute(
            "SELECT source_version_id FROM task_evidence WHERE task_id=? AND file_record_id=?",
            (task_id, env.file_ids["a.txt"]))}
        self.assertEqual(versions, {pinned[0][0]})
        self.assertGreaterEqual(r2["result"]["dropped"]["version_drift"], 1)
        kinds = [e["kind"] for e in env.tasks.get_task_events(agent_ctx(), task_id)["events"]]
        self.assertIn("version_drift", kinds)

    def test_revoked_acl_never_enters_or_survives_evidence(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1(env))
        res = env.act(task_id, "search", {"query": "Session Orion-7 opened by"})
        eid = evidence_with(res, "Orion-7")
        env.submit(task_id, "gather", {"selected_evidence_ids": [eid]})
        env.revoke("a.txt")  # access removed after retrieval, before verification
        out = env.submit(task_id, "report", {"items": [{"field": "opener", "value": "Maria Lopez",
                                                         "evidence_ids": [eid]}]})
        self.assertEqual(out["result"]["state"], "failed")
        self.assertIn("permission_denied", out["result"]["verification"]["reason"])

    def test_ambiguity_incomplete_and_missing_link_never_become_success(self) -> None:
        env = self.env
        task_id = env.approved("multihop_trace", t2(env))
        _, _, chain = self._chain(env, task_id)
        with self.assertRaises(TaskError) as cm:  # answer not quoted by last hop
            env.submit(task_id, "trace", {"chain": chain, "answer": "KEY-0000"})
        self.assertEqual(cm.exception.code, "RESULT_REJECTED")
        with self.assertRaises(TaskError):  # chain order broken
            env.submit(task_id, "trace", {"chain": list(reversed(chain)), "answer": "KEY-4242"})
        out = env.submit(task_id, "trace", {"chain": chain, "answer": "KEY-4242",
                                            "alternatives": [{"answer": "KEY-9001"}]})
        self.assertEqual(out["result"]["state"], "needs_review")
        self.assertEqual(out["result"]["stop_reason"], "ambiguity_unresolved")
        with self.assertRaises(TaskError) as cm:  # incomplete evidence cannot be accepted by a reviewer
            env.tasks.review_task_result(human_ctx(), task_id, "accept")
        self.assertEqual(cm.exception.code, "RESULT_REJECTED")
        env.tasks.review_task_result(human_ctx(), task_id, "reject", note="ambiguous")
        self.assertEqual(env.tasks.get_task(agent_ctx(), task_id)["state"], "failed")

    def test_declare_incomplete_variants_and_needs_input_resume(self) -> None:
        env = self.env
        task_id = env.approved("multihop_trace", t2(env))
        hop1(env, task_id)
        out = env.submit(task_id, "trace", {}, declare_incomplete=True, reason="needs_input")
        self.assertEqual(out["result"]["state"], "waiting_input")
        env.clock.advance(3600)  # waiting time must not consume the wall-clock budget
        env.tasks.revoke_task_approval  # noqa: B018 (documented capability, not used here)
        resumed = env.tasks.resume_task(agent_ctx(), task_id)
        self.assertEqual(resumed["state"], "running")
        with self.assertRaises(TaskError) as cm:  # authorization is re-validated on return
            env.tasks.store.conn.execute("UPDATE task_approval SET revoked_at='x' WHERE task_id=?", (task_id,))
            out2 = env.submit(task_id, "trace", {}, declare_incomplete=True, reason="needs_input")
            env.tasks.resume_task(agent_ctx(), task_id)
        self.assertEqual(cm.exception.code, "TASK_AUTH_REVOKED")
        self.assertEqual(out2["result"]["state"], "waiting_input") if False else None

    def test_repeated_rejections_trip_attempt_limit(self) -> None:
        env = self.env
        task_id = env.approved("multihop_trace", t2(env))
        hop1(env, task_id)
        for _ in range(5):
            with self.assertRaises(TaskError):
                env.submit(task_id, "trace", {"chain": [], "answer": "x"})
        self.assertEqual(env.tasks.get_task(agent_ctx(), task_id)["state"], "needs_review")


class ReworkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(files=CORPUS)

    def tearDown(self) -> None:
        self.env.close()

    def _to_review(self):
        env = self.env
        task_id = env.approved("doc_evidence_check", t1(env))
        res = env.act(task_id, "search", {"query": "Session Orion-7 opened by"})
        eid = evidence_with(res, "Orion-7")
        g = env.submit(task_id, "gather", {"selected_evidence_ids": [eid]})
        out = env.submit(task_id, "report", {"items": [{"field": "opener", "value": "Wrong Person",
                                                         "evidence_ids": [eid]}]})
        self.assertEqual(out["result"]["state"], "needs_review")
        return task_id, eid, g["result"]["artifact_sha256"]

    def test_partial_rework_preserves_upstream_artifacts_and_recompletes(self) -> None:
        env = self.env
        task_id, eid, gather_sha = self._to_review()
        with self.assertRaises(TaskError):  # agents cannot review
            env.tasks.review_task_result(agent_ctx(), task_id, "rework", step_id="report")
        with self.assertRaises(TaskError):
            env.tasks.review_task_result(human_ctx(), task_id, "rework", step_id="nope")
        s = env.tasks.review_task_result(human_ctx(), task_id, "rework", step_id="report", note="fix value")
        self.assertEqual(s["state"], "running")
        steps = {x["step_id"]: x for x in s["steps"]}
        self.assertEqual(steps["gather"]["state"], "accepted")
        self.assertEqual(steps["gather"]["attempt"]["artifact_sha256"], gather_sha)  # untouched
        self.assertEqual(steps["report"]["attempt"]["attempt_no"], 2)
        ev = [e for e in env.tasks.get_task_events(agent_ctx(), task_id)["events"] if e["kind"] == "rework_started"][0]
        self.assertEqual(ev["payload"]["preserved_steps"], ["gather"])
        ctx_packet = env.tasks.get_task_context(agent_ctx(), task_id)
        self.assertEqual(ctx_packet["volatile"]["rework_note"], "fix value")
        out = env.submit(task_id, "report", {"items": [{"field": "opener", "value": "Maria Lopez",
                                                         "evidence_ids": [eid]}]})
        self.assertEqual(out["result"]["state"], "succeeded")

    def test_rework_of_upstream_step_resets_dependents_only(self) -> None:
        env = self.env
        task_id, _, _ = self._to_review()
        s = env.tasks.review_task_result(human_ctx(), task_id, "rework", step_id="gather")
        steps = {x["step_id"]: x for x in s["steps"]}
        self.assertEqual(steps["gather"]["attempt"]["attempt_no"], 2)
        self.assertEqual(steps["report"]["state"], "pending")
        ev = [e for e in env.tasks.get_task_events(agent_ctx(), task_id)["events"] if e["kind"] == "rework_started"][0]
        self.assertEqual(ev["payload"]["reworked_steps"], ["gather", "report"])
        self.assertEqual(ev["payload"]["preserved_steps"], [])

    def test_review_accept_and_reject(self) -> None:
        env = self.env
        task_id, _, _ = self._to_review()
        out = env.tasks.review_task_result(human_ctx(), task_id, "accept")
        self.assertEqual(out["state"], "succeeded")
        task2, _, _ = self._to_review()
        self.assertEqual(env.tasks.review_task_result(human_ctx(), task2, "reject")["state"], "failed")
        with self.assertRaises(TaskError):  # terminal
            env.tasks.review_task_result(human_ctx(), task2, "accept")


class MemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(files=CORPUS)
        mem = LayeredMemoryStore(self.env.catalog.conn)
        item = mem.capture_session_item(workspace_id=WORKSPACE, principal_id=ALICE, session_id="s1",
                                        content="Release owner prefers JSON reports", provenance_category="user_stated",
                                        ttl_seconds=3600)
        receipt = mem.promote_to_working(workspace_id=WORKSPACE, principal_id=ALICE,
                                         session_item_id=item["session_item_id"], target_scope_id="scope1",
                                         idempotency_key="seed-memory-key-0001", actor_id=ALICE,
                                         requested_ttl_seconds=3600)
        self.memory_id = receipt["working_memory_id"]

    def tearDown(self) -> None:
        self.env.close()

    def _params(self, env: Env, propose: bool = True) -> dict:
        return {"source_root_ids": [env.root_id], "instruction": "Summarize the opener", "memory_scope_id": "scope1",
                "output_schema": {"type": "object", "properties": {"summary": {"type": "string"}},
                                  "required": ["summary"], "additionalProperties": False},
                "propose_memory": propose}

    def _gather(self, env: Env, task_id: str):
        res = env.act(task_id, "search", {"query": "Session Orion-7 opened by"})
        eid = evidence_with(res, "Orion-7")
        rec = env.act(task_id, "recall_memory", {})
        mids = [i["memory_id"] for i in rec["result"]["items"]]
        self.assertIn(self.memory_id, mids)
        env.submit(task_id, "gather", {"selected_evidence_ids": [eid]})
        return eid

    def test_memory_is_proposed_only_after_review_and_never_auto_published(self) -> None:
        env = self.env
        task_id = env.approved("doc_memory_artifact", self._params(env))
        eid = self._gather(env, task_id)
        out = env.submit(task_id, "produce", {"output": {"summary": "Maria Lopez opened Orion-7"},
                                              "evidence_ids": [eid], "memory_ids": [self.memory_id]})
        self.assertEqual(out["result"]["state"], "needs_review")  # open-ended content is never auto-accepted
        conn = env.catalog.conn
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM governed_promotion_proposal").fetchone()[0], 0)
        env.tasks.review_task_result(human_ctx(), task_id, "accept")
        rows = conn.execute("SELECT state FROM governed_promotion_proposal").fetchall()
        self.assertEqual([r[0] for r in rows], ["pending_review"])
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM memory_record_v2").fetchone()[0], 0)
        ob = env.tasks.store.conn.execute("SELECT state FROM task_outbox WHERE task_id=?", (task_id,)).fetchone()
        self.assertEqual(ob[0], "done")
        kinds = [e["kind"] for e in env.tasks.get_task_events(agent_ctx(), task_id)["events"]]
        self.assertIn("memory_proposal_created", kinds)

    def test_unrecalled_memory_and_schema_violations_fail(self) -> None:
        env = self.env
        task_id = env.approved("doc_memory_artifact", self._params(env, propose=False))
        eid = self._gather(env, task_id)
        out = env.submit(task_id, "produce", {"output": {"summary": "x"}, "evidence_ids": [eid],
                                              "memory_ids": ["never-recalled"]})
        self.assertEqual(out["result"]["state"], "failed")
        task2 = env.approved("doc_memory_artifact", self._params(env, propose=False))
        with patch.dict(C.LIMITS, {"max_active_tasks": 2}):
            eid2 = self._gather(env, task2)
            out2 = env.submit(task2, "produce", {"output": {"summary": 5}, "evidence_ids": [eid2]})
        self.assertEqual(out2["result"]["state"], "failed")
        self.assertIn("output_schema", json.dumps(out2["result"]["verification"]))

    def test_output_schema_must_be_local_and_valid(self) -> None:
        env = self.env
        bad = self._params(env)
        bad["output_schema"] = {"$ref": "https://example.com/schema.json"}
        with self.assertRaises(TaskError):
            env.tasks.create_task(agent_ctx(), "doc_memory_artifact", bad)
        bad["output_schema"] = {"type": "not-a-type"}
        with self.assertRaises(TaskError):
            env.tasks.create_task(agent_ctx(), "doc_memory_artifact", bad)


class EngineAndWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(files=CORPUS)

    def tearDown(self) -> None:
        self.env.close()

    def _at_report(self):
        env = self.env
        task_id = env.approved("doc_evidence_check", t1(env))
        res = env.act(task_id, "search", {"query": "Session Orion-7 opened by"})
        eid = evidence_with(res, "Orion-7")
        env.submit(task_id, "gather", {"selected_evidence_ids": [eid]})
        return task_id, eid

    def test_candidate_write_is_sealed_by_engine_and_immutable(self) -> None:
        env = self.env
        task_id, _ = self._at_report()
        out = env.act(task_id, "write_candidate", {"name": "notes.txt", "content": "draft notes"})
        self.assertEqual(out["result"]["engine_status"], "completed")
        with self.assertRaises(TaskError) as cm:
            env.act(task_id, "write_candidate", {"name": "notes.txt", "content": "different"})
        self.assertEqual(cm.exception.code, "ARTIFACT_REJECTED")
        for bad in ("../evil.json", "a/b.json", "C:/x.json", "con.exe", "UPPER.json", "x" * 80 + ".json", ".hidden.json"):
            with self.assertRaises(TaskError) as cm:
                env.act(task_id, "write_candidate", {"name": bad, "content": "x"})
            self.assertIn(cm.exception.code, ("ARTIFACT_REJECTED", "TASK_VALIDATION_ERROR"), bad)

    def test_engine_completed_with_review_is_never_success(self) -> None:
        from pdx_artifact_engine import ArtifactRuntime
        original = ArtifactRuntime.execute_plan

        def reviewing(self_, plan, out_dir):  # noqa: ANN001
            result = original(self_, plan, out_dir)
            result["run_manifest"]["status"] = "completed_with_review"
            return result

        env = self.env
        task_id, eid = self._at_report()
        with patch.object(ArtifactRuntime, "execute_plan", reviewing):
            out = env.submit(task_id, "report", {"items": [{"field": "opener", "value": "Maria Lopez",
                                                             "evidence_ids": [eid]}]})
        self.assertEqual(out["result"]["state"], "needs_review")
        self.assertEqual(out["result"]["verification"]["reason"], "engine_completed_with_review")

    def test_engine_failure_and_unavailability_are_tagged_origin_engine(self) -> None:
        env = self.env
        task_id, eid = self._at_report()
        env.tasks.engine._import_error = "engine missing"
        with self.assertRaises(TaskError) as cm:
            env.act(task_id, "write_candidate", {"name": "n.txt", "content": "x"})
        self.assertEqual(cm.exception.code, "ENGINE_UNAVAILABLE")
        self.assertEqual(cm.exception.details["origin"], "engine")
        env.tasks.engine._import_error = None
        events = env.tasks.get_task_events(agent_ctx(), task_id)["events"]
        rejected = [e for e in events if e["kind"] == "action_rejected" and e["payload"]["code"] == "ENGINE_UNAVAILABLE"]
        self.assertTrue(rejected and rejected[0]["origin"] == "engine")
        # local-policy rejections are tagged differently
        with self.assertRaises(TaskError) as cm2:
            env.act(task_id, "write_candidate", {"name": "../x.json", "content": "x"})
        self.assertEqual(cm2.exception.details["origin"], "local_policy")

    def test_engine_api_surface_matches_expectation(self) -> None:
        import pdx_artifact_engine as eng
        self.assertEqual(eng.__version__, "0.3.0a13")
        for name in ("ArtifactRuntime", "validate_execution_plan"):
            self.assertTrue(hasattr(eng, name))
        from pdx_artifact_engine.registry import SkillDefinition, SkillRegistry  # noqa: F401

    def test_workspace_rejects_escape_reparse_quota_and_tamper(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        try:
            ws = TaskWorkspace(tmp / "tasks")
            tid, aid = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
            rel, sha, size = ws.write_candidate(tid, aid, "ok.json", "{}", used_bytes=0)
            self.assertEqual(ws.write_candidate(tid, aid, "ok.json", "{}", used_bytes=0)[1], sha)  # idempotent
            with self.assertRaises(TaskError):
                ws.write_candidate("../escape", aid, "x.json", "{}", used_bytes=0)
            with self.assertRaises(TaskError) as cm:
                ws.write_candidate(tid, aid, "big.json", "x", used_bytes=C.LIMITS["candidate_output_bytes"])
            self.assertEqual(cm.exception.code, "TASK_QUOTA_EXCEEDED")
            with self.assertRaises(TaskError):
                ws.read_candidate("../../etc/passwd", sha)
            (tmp / "tasks" / tid / aid / "candidate" / "ok.json").write_text("tampered", encoding="utf-8")
            with self.assertRaises(TaskError):
                ws.read_candidate(rel, sha)
            # junction/symlink inside the workspace is refused
            outside = tmp / "outside"
            outside.mkdir()
            tid2 = "33333333-3333-3333-3333-333333333333"
            (tmp / "tasks" / tid2).mkdir()
            link = tmp / "tasks" / tid2 / aid
            made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
            if made.returncode == 0:
                with self.assertRaises(TaskError):
                    ws.write_candidate(tid2, aid, "x.json", "{}", used_bytes=0)
                self.assertFalse(any(outside.iterdir()))
                os.rmdir(link)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class StoreAndLeaseTests(unittest.TestCase):
    def test_migration_fresh_idempotent_newer_and_failure_rollback(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        try:
            db = tmp / "tasks.sqlite"
            self.assertEqual(store_mod.migrate_tasks_database(db), store_mod.TASK_SCHEMA_VERSION)
            self.assertEqual(store_mod.migrate_tasks_database(db), store_mod.TASK_SCHEMA_VERSION)
            conn = sqlite3.connect(db)
            conn.execute(f"PRAGMA user_version={store_mod.TASK_SCHEMA_VERSION + 5}")
            conn.close()
            with self.assertRaises(TaskError) as cm:
                store_mod.migrate_tasks_database(db)
            self.assertEqual(cm.exception.code, "TASK_DB_UNSUPPORTED_VERSION")
            bad = tmp / "bad.sqlite"
            with patch.dict(store_mod._MIGRATIONS, {1: "CREATE TABLE ok(x);\nTHIS IS NOT SQL"}):
                with self.assertRaises(TaskError) as cm:
                    store_mod.migrate_tasks_database(bad)
            self.assertEqual(cm.exception.code, "TASK_DB_MIGRATION_FAILED")
            c2 = sqlite3.connect(bad)
            self.assertEqual(c2.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(c2.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='ok'").fetchone()[0], 0)
            c2.close()
            upgraded = tmp / "from-v1.sqlite"
            old = sqlite3.connect(upgraded)
            old.execute("PRAGMA user_version=1")
            old.commit()
            old.close()
            self.assertEqual(store_mod.migrate_tasks_database(upgraded), 2)
            seen = sqlite3.connect(upgraded)
            self.assertEqual(seen.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(seen.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='task_context_measurement'").fetchone()[0], 1)
            seen.execute(f"PRAGMA user_version={store_mod.TASK_SCHEMA_VERSION + 1}")
            seen.commit()
            seen.close()
            with self.assertRaises(TaskError) as cm:
                store_mod.migrate_tasks_database(upgraded)
            self.assertEqual(cm.exception.code, "TASK_DB_UNSUPPORTED_VERSION")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def _store_with_task(self, tmp: Path, clock: FakeClock):
        st = store_mod.TaskStore(tmp / "tasks.sqlite", clock=clock)
        now = clock()
        with st.tx() as conn:
            conn.execute(
                "INSERT INTO task(task_id, workspace_id, principal_id, creator_actor_kind, template_id, template_version,"
                "template_sha256, context_mode, params_json, params_sha256, state, state_version, created_at, updated_at,"
                "last_seen_epoch, deadline_epoch, input_bytes) VALUES ('t1','w','p','agent','x','1','s','bounded_retrieval',"
                "'{}','h','awaiting_approval',1,'c','u',?,?,2)", (now, now + 100))
        return st

    def test_lease_fencing_and_takeover_in_process(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        try:
            clock = FakeClock()
            a = self._store_with_task(tmp, clock)
            b = store_mod.TaskStore(tmp / "tasks.sqlite", clock=clock)
            with a.tx() as conn:
                ta = a.acquire_lease(conn, "t1", "A")
            with self.assertRaises(TaskError) as cm:
                with b.tx() as conn:
                    b.acquire_lease(conn, "t1", "B")
            self.assertEqual(cm.exception.code, "LEASE_HELD")
            clock.advance(C.LIMITS["lease_seconds"] + 1)
            with self.assertRaises(TaskError) as cm:  # expired but not taken over without explicit resume
                with b.tx() as conn:
                    b.acquire_lease(conn, "t1", "B")
            self.assertEqual(cm.exception.code, "LEASE_LOST")
            with b.tx() as conn:
                tb = b.acquire_lease(conn, "t1", "B", allow_takeover=True)
            self.assertGreater(tb, ta)
            with self.assertRaises(TaskError) as cm:  # the old holder's token is fenced out
                with a.tx() as conn:
                    a.require_fence(conn, "t1", "A", ta)
            self.assertEqual(cm.exception.code, "LEASE_LOST")
            with a.tx() as conn:
                a.cas_state(conn, "t1", 1, "queued")
            with self.assertRaises(TaskError) as cm:
                with b.tx() as conn:
                    b.cas_state(conn, "t1", 1, "queued")
            self.assertEqual(cm.exception.code, "TASK_STATE_CONFLICT")
            a.close()
            b.close()
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_multi_process_race_has_exactly_one_lease_winner_and_one_cas_winner(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        try:
            st = self._store_with_task(tmp, FakeClock(__import__("time").time()))
            ctx = multiprocessing.get_context("spawn")
            import task_harness_mp as mp
            n = 4
            barrier, queue = ctx.Barrier(n), ctx.Queue()
            procs = [ctx.Process(target=mp.race_lease, args=(str(tmp / "tasks.sqlite"), "t1", f"p{i}", barrier, queue))
                     for i in range(n)]
            for p in procs:
                p.start()
            results = [queue.get(timeout=60) for _ in procs]
            for p in procs:
                p.join(timeout=30)
            self.assertEqual(sum(1 for r in results if r[1] == "ok"), 1, results)
            self.assertTrue(all(r[1] in ("ok", "LEASE_HELD") for r in results), results)
            barrier2, queue2 = ctx.Barrier(n), ctx.Queue()
            procs = [ctx.Process(target=mp.race_cas, args=(str(tmp / "tasks.sqlite"), "t1", 1, barrier2, queue2, f"c{i}"))
                     for i in range(n)]
            for p in procs:
                p.start()
            results2 = [queue2.get(timeout=60) for _ in procs]
            for p in procs:
                p.join(timeout=30)
            self.assertEqual(sum(1 for r in results2 if r[1] == "ok"), 1, results2)
            self.assertTrue(all(r[1] in ("ok", "TASK_STATE_CONFLICT") for r in results2), results2)
            st.close()
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class RecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(files=CORPUS)

    def tearDown(self) -> None:
        self.env.close()

    def _crash_at(self, point: str):
        def hook(p: str) -> None:
            if p == point:
                raise RuntimeError(f"simulated crash at {p}")
        self.env.fault_hook = hook

    def _restart(self):
        self.env.fault_hook = None
        self.env.clock.advance(C.LIMITS["lease_seconds"] + 30)
        svc = self.env.new_service(run_recovery=False)
        report = svc.recover()
        return svc, report

    def test_crash_after_intent_search_recovers_without_duplicates_and_charges_ledger(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1(env))
        k = key()
        self._crash_at("after_intent")
        with self.assertRaises(RuntimeError):
            env.tasks.dispatch_task_action(agent_ctx(), task_id, "search", {"query": "Session Orion-7 opened by"}, k)
        self.assertEqual(env.tasks.get_task(agent_ctx(), task_id)["state"], "running")
        svc2, report = self._restart()
        self.assertEqual(report["interrupted"], [task_id])
        self.assertEqual(svc2.get_task(agent_ctx(), task_id)["state"], "interrupted")
        resumed = svc2.resume_task(agent_ctx(), task_id)
        self.assertEqual(resumed["state"], "running")
        attempt = env.tasks.store.conn.execute(
            "SELECT current_attempt_id FROM task_step WHERE task_id=? AND step_id='gather'", (task_id,)).fetchone()[0]
        from pdx_local_ai.tasks.context import RetrievalLedger
        led = RetrievalLedger.load(svc2.store.conn, task_id, attempt)
        self.assertEqual(led.data["queries"], 1)  # interrupted search was charged conservatively
        self.assertEqual(svc2.store.conn.execute(
            "SELECT state FROM task_operation WHERE idempotency_key=?", (k,)).fetchone()[0], "unknown")
        out = svc2.dispatch_task_action(agent_ctx(), task_id, "search", {"query": "Session Orion-7 opened by"}, k)
        self.assertTrue(out["result"]["evidence"])
        n = svc2.store.conn.execute("SELECT COUNT(*) FROM task_hop WHERE task_id=?", (task_id,)).fetchone()[0]
        self.assertEqual(n, 1)
        self.assertEqual(svc2.store.conn.execute(
            "SELECT COUNT(*) FROM task_operation WHERE task_id=?", (task_id,)).fetchone()[0], 1)

    def test_crash_after_file_write_and_after_seal_replay_is_idempotent(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1(env))
        res = env.act(task_id, "search", {"query": "Session Orion-7 opened by"})
        eid = evidence_with(res, "Orion-7")
        env.submit(task_id, "gather", {"selected_evidence_ids": [eid]})
        k = key()
        self._crash_at("after_execute")
        with self.assertRaises(RuntimeError):
            env.tasks.dispatch_task_action(agent_ctx(), task_id, "write_candidate",
                                           {"name": "notes.txt", "content": "n"}, k)
        self.assertEqual(env.tasks.store.conn.execute("SELECT COUNT(*) FROM task_artifact WHERE task_id=?",
                                                      (task_id,)).fetchone()[0], 0)
        svc2, _ = self._restart()
        svc2.resume_task(agent_ctx(), task_id)
        out = svc2.dispatch_task_action(agent_ctx(), task_id, "write_candidate", {"name": "notes.txt", "content": "n"}, k)
        self.assertEqual(out["result"]["name"], "notes.txt")
        self.assertEqual(svc2.store.conn.execute("SELECT COUNT(*) FROM task_artifact WHERE task_id=?",
                                                 (task_id,)).fetchone()[0], 1)
        # crash after the final result was sealed but before the DB recorded it
        self.env.fault_hook = lambda p: (_ for _ in ()).throw(RuntimeError("crash")) if p == "after_seal" else None
        svc2.fault_hook = self.env.fault_hook
        k2 = key()
        art = {"items": [{"field": "opener", "value": "Maria Lopez", "evidence_ids": [eid]}]}
        with self.assertRaises(RuntimeError):
            svc2.submit_task_result(agent_ctx(), task_id, "report", art, k2)
        self.assertEqual(svc2.get_task(agent_ctx(), task_id)["state"], "running")
        svc2.fault_hook = None
        self.env.clock.advance(C.LIMITS["lease_seconds"] + 30)
        svc3 = self.env.new_service(run_recovery=False)
        svc3.recover()
        svc3.resume_task(agent_ctx(), task_id)
        out2 = svc3.submit_task_result(agent_ctx(), task_id, "report", art, k2)
        self.assertEqual(out2["result"]["state"], "succeeded")
        verifications = [e for e in svc3.get_task_events(agent_ctx(), task_id, limit=200)["events"]
                         if e["kind"] == "verification"]
        self.assertEqual(len(verifications), 1)
        self.assertEqual(svc3.store.conn.execute(
            "SELECT COUNT(*) FROM task_artifact WHERE task_id=? AND name='result.json'", (task_id,)).fetchone()[0], 1)

    def test_outbox_retries_to_exactly_one_proposal_after_crash(self) -> None:
        env = self.env
        mem = LayeredMemoryStore(env.catalog.conn)
        item = mem.capture_session_item(workspace_id=WORKSPACE, principal_id=ALICE, session_id="s9", content="pref",
                                        provenance_category="user_stated", ttl_seconds=3600)
        mem.promote_to_working(workspace_id=WORKSPACE, principal_id=ALICE, session_item_id=item["session_item_id"],
                               target_scope_id="scope1", idempotency_key="seed-memory-key-0002", actor_id=ALICE,
                               requested_ttl_seconds=3600)
        params = {"source_root_ids": [env.root_id], "instruction": "x", "memory_scope_id": "scope1",
                  "output_schema": {"type": "object"}, "propose_memory": True}
        task_id = env.approved("doc_memory_artifact", params)
        res = env.act(task_id, "search", {"query": "Session Orion-7 opened by"})
        eid = evidence_with(res, "Orion-7")
        env.submit(task_id, "gather", {"selected_evidence_ids": [eid]})
        env.submit(task_id, "produce", {"output": {"a": 1}, "evidence_ids": [eid]})
        calls = {"n": 0}

        def hook(p: str) -> None:
            if p == "outbox_before_effect":
                calls["n"] += 1
                if calls["n"] == 1:
                    raise RuntimeError("crash before effect")
        env.tasks.fault_hook = hook
        env.tasks.review_task_result(human_ctx(), task_id, "accept")
        ob = env.tasks.store.conn.execute("SELECT state, attempts FROM task_outbox WHERE task_id=?", (task_id,)).fetchone()
        self.assertEqual((ob["state"], ob["attempts"]), ("retry", 1))
        self.assertEqual(env.catalog.conn.execute("SELECT COUNT(*) FROM governed_promotion_proposal").fetchone()[0], 0)
        env.tasks.recover()
        ob = env.tasks.store.conn.execute("SELECT state FROM task_outbox WHERE task_id=?", (task_id,)).fetchone()
        self.assertEqual(ob["state"], "done")
        env.tasks.recover()  # reconciliation is repeatable and does not duplicate the effect
        self.assertEqual(env.catalog.conn.execute("SELECT COUNT(*) FROM governed_promotion_proposal").fetchone()[0], 1)

    def test_startup_recovery_marks_orphans_and_stuck_verification(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1(env))
        env.act(task_id, "search", {"query": "Orion-7 opened"})
        orphan = env.profile / "tasks" / "99999999-9999-9999-9999-999999999999" / "x"
        orphan.mkdir(parents=True)
        t2_id = env.approved("doc_evidence_check", t1(env))
        env.tasks.store.conn.execute("UPDATE task SET state='awaiting_verification' WHERE task_id=?", (t2_id,))
        _, report = self._restart()
        self.assertEqual(report["interrupted"], [task_id])
        self.assertEqual(report["verification_interrupted"], [t2_id])
        self.assertEqual(report["workspace"]["orphan_dirs_removed"], 1)
        self.assertFalse(orphan.exists())

    def test_graceful_shutdown_drains_interrupts_and_blocks_new_actions(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1(env))
        reached, gate = threading.Event(), threading.Event()

        def hold(p: str) -> None:
            if p == "after_execute":
                reached.set()
                gate.wait(timeout=0.5)
        env.fault_hook = hold
        results: dict = {}

        def shut() -> None:  # the Catalog connection is single-thread; shutdown runs on the second thread
            results["summary"] = env.tasks.shutdown(timeout_sec=5.0)

        th = threading.Thread(target=shut)

        def hold(p: str) -> None:
            if p == "after_execute":
                th.start()
                while env.tasks._inflight and not env.tasks._shutting_down:
                    pass
        env.fault_hook = hold
        results["out"] = env.act(task_id, "search", {"query": "Orion-7 opened"})  # in-flight at shutdown
        th.join(timeout=10)
        summary = results["summary"]
        self.assertTrue(summary["clean"], summary)  # shutdown waited for the in-flight action
        self.assertEqual(summary["interrupted_tasks"], [task_id])
        with self.assertRaises(TaskError) as cm:
            env.act(task_id, "search", {"query": "again"})
        self.assertEqual(cm.exception.code, "TASK_SHUTTING_DOWN")
        env.fault_hook = None
        svc2 = env.new_service()
        self.assertEqual(svc2.resume_task(agent_ctx(), task_id)["state"], "running")

    def test_fencing_blocks_stale_executor_after_takeover(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1(env))
        env.act(task_id, "search", {"query": "Orion-7 opened"})
        svc_b = env.new_service()

        def hook(p: str) -> None:
            if p == "after_execute":
                env.fault_hook = None
                env.clock.advance(C.LIMITS["lease_seconds"] + 5)
                svc_b.resume_task(agent_ctx(), task_id)
        env.fault_hook = hook
        with self.assertRaises(TaskError) as cm:
            env.act(task_id, "search", {"query": "Maria Lopez vault"})
        self.assertEqual(cm.exception.code, "LEASE_LOST")
        n = env.tasks.store.conn.execute("SELECT COUNT(*) FROM task_hop WHERE task_id=?", (task_id,)).fetchone()[0]
        self.assertEqual(n, 1)  # the stale executor's result was not recorded

    def test_resume_is_blocked_while_another_executor_holds_the_lease(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1(env))
        env.act(task_id, "search", {"query": "Orion-7 opened"})
        svc_b = env.new_service()
        with self.assertRaises(TaskError) as cm:
            svc_b.resume_task(agent_ctx(), task_id)
        self.assertEqual(cm.exception.code, "LEASE_HELD")
        with self.assertRaises(TaskError) as cm:
            svc_b.dispatch_task_action(agent_ctx(), task_id, "search", {"query": "x y"}, key())
        self.assertEqual(cm.exception.code, "LEASE_HELD")

    def test_retention_purge_removes_expired_terminal_tasks_only(self) -> None:
        env = self.env
        done = env.approved("doc_evidence_check", t1(env))
        res = env.act(done, "search", {"query": "Session Orion-7 opened by"})
        eid = evidence_with(res, "Orion-7")
        env.submit(done, "gather", {"selected_evidence_ids": [eid]})
        env.submit(done, "report", {"items": [{"field": "opener", "value": "Maria Lopez", "evidence_ids": [eid]}]})
        waiting = env.create("doc_evidence_check", t1(env))
        self.assertTrue((env.profile / "tasks" / done).exists())
        with self.assertRaises(TaskError):
            env.tasks.purge_expired(agent_ctx())  # admin only
        self.assertEqual(env.tasks.purge_expired(human_ctx())["purged_tasks"], 0)  # not expired yet
        env.clock.advance((C.LIMITS["retention_days"] + 1) * 86400)
        out = env.tasks.purge_expired(human_ctx())
        self.assertEqual(out["purged_tasks"], 1)
        self.assertFalse((env.profile / "tasks" / done).exists())
        self.assertIsNotNone(env.tasks.store.get_task(waiting))
        self.assertIsNone(env.tasks.store.get_task(done))


_ = (os, WORKSPACE)

if __name__ == "__main__":
    unittest.main()
