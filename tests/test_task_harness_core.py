"""Task harness: contracts, lifecycle, permissions, idempotency, limits, verification."""

from __future__ import annotations

import json
import re
import sqlite3
import unittest
from unittest.mock import patch

from task_harness_support import (
    ALICE, BOB, CORPUS, WORKSPACE, Env, FakeClock, agent_ctx, evidence_with, human_ctx, key,
    scripted_multihop_driver,
)

from pdx_local_ai.service.contracts import SecurityContext
from pdx_local_ai.tasks import contracts as C
from pdx_local_ai.tasks.contracts import TaskError

T1_PARAMS = {"questions": [{"field": "opener", "question": "Who opened session Orion-7?"}]}


def t1_params(env: Env) -> dict:
    return {"source_root_ids": [env.root_id], **T1_PARAMS}


def run_t1_to_report(env: Env, task_id: str, *, value: str = "Maria Lopez") -> dict:
    res = env.act(task_id, "search", {"query": "Session Orion-7 opened by"})
    eid = evidence_with(res, "Orion-7")
    env.submit(task_id, "gather", {"selected_evidence_ids": [eid]})
    return env.submit(task_id, "report", {"items": [{"field": "opener", "value": value, "evidence_ids": [eid]}]})


class ContractTests(unittest.TestCase):
    def test_transition_table_is_closed_and_terminal_states_have_no_exits(self) -> None:
        self.assertEqual(set(C.TRANSITIONS), set(C.TASK_STATES))
        for state in C.TERMINAL_STATES:
            self.assertEqual(C.TRANSITIONS[state], frozenset())
        for src, targets in C.TRANSITIONS.items():
            self.assertTrue(targets <= set(C.TASK_STATES), src)
        # needs_review is never a path to success without a reviewer decision
        self.assertNotIn(C.SUCCEEDED, C.TRANSITIONS[C.RUNNING])
        with self.assertRaises(TaskError) as cm:
            C.check_transition(C.SUCCEEDED, C.RUNNING)
        self.assertEqual(cm.exception.code, "TASK_INVALID_TRANSITION")

    def test_permission_matrix_covers_every_tool_and_error_codes_are_closed(self) -> None:
        from pdx_local_ai.tasks.mcp_tools import TASK_TOOL_NAMES
        self.assertTrue(TASK_TOOL_NAMES - {"approve_task", "review_task_result"} <= set(C.PERMISSION_MATRIX))
        self.assertIn("approve_task", C.PERMISSION_MATRIX)
        self.assertEqual(C.PERMISSION_MATRIX["recall_published_memory"], "owner")
        with self.assertRaises(AssertionError):
            TaskError("NOT_A_DECLARED_CODE", "x")
        self.assertEqual(TaskError("TASK_NOT_FOUND", "x").details["origin"], "local_policy")

    def test_templates_are_versioned_and_grant_no_permissions(self) -> None:
        from pdx_local_ai.tasks.templates import public_templates
        out = public_templates()
        self.assertEqual({t["template_id"] for t in out},
                         {"doc_evidence_check", "multihop_trace", "doc_memory_artifact"})
        for t in out:
            self.assertFalse(t["grants_permissions"])
            self.assertEqual(len(t["template_sha256"]), 64)


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(files=CORPUS)

    def tearDown(self) -> None:
        self.env.close()

    def test_happy_path_requires_human_approval_and_verifies_evidence(self) -> None:
        env = self.env
        task_id = env.create("doc_evidence_check", t1_params(env))
        self.assertEqual(env.tasks.get_task(agent_ctx(), task_id)["state"], "awaiting_approval")
        with self.assertRaises(TaskError) as cm:  # not approved: cannot act
            env.act(task_id, "search", {"query": "Orion-7"})
        self.assertEqual(cm.exception.code, "ACTION_NOT_ALLOWED")
        with self.assertRaises(TaskError) as cm:  # agent connection has no approver capability
            env.tasks.approve_task(agent_ctx(), task_id)
        self.assertEqual(cm.exception.code, "TASK_PERMISSION_DENIED")
        with self.assertRaises(TaskError) as cm:  # even with the flag an agent cannot approve its own task
            env.tasks.approve_task(agent_ctx(can_approve_tasks=True), task_id)
        self.assertEqual(cm.exception.code, "SELF_APPROVAL_DENIED")
        env.tasks.approve_task(human_ctx(), task_id)
        self.assertEqual(env.tasks.get_task(agent_ctx(), task_id)["state"], "queued")
        out = run_t1_to_report(env, task_id)
        self.assertEqual(out["result"]["state"], "succeeded")
        summary = env.tasks.get_task(agent_ctx(), task_id)
        self.assertEqual(summary["verification"]["outcome"], "succeeded")
        self.assertTrue(all(c["status"] == "pass" for c in summary["verification"]["checks"]))
        names = {a["name"] for a in summary["artifacts"]}
        self.assertIn("result.json", names)
        events = env.tasks.get_task_events(agent_ctx(), task_id)["events"]
        engine = [e for e in events if e["kind"] == "engine_run"]
        self.assertTrue(engine and all(e["origin"] == "engine" for e in engine))
        self.assertEqual(engine[0]["payload"]["status"], "completed")
        self.assertEqual(summary["state"], "succeeded")
        self.assertIsNotNone(summary["retain_until"])

    def test_unverifiable_value_goes_to_needs_review_never_success(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        out = run_t1_to_report(env, task_id, value="Somebody Else")
        self.assertEqual(out["result"]["state"], "needs_review")
        self.assertEqual(out["result"]["verification"]["outcome"], "needs_review")

    def test_fabricated_citation_fails_verification(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        res = env.act(task_id, "search", {"query": "Session Orion-7 opened by"})
        eid = evidence_with(res, "Orion-7")
        env.submit(task_id, "gather", {"selected_evidence_ids": [eid]})
        out = env.submit(task_id, "report", {"items": [{"field": "opener", "value": "Maria Lopez",
                                                         "evidence_ids": ["not-a-real-evidence-id"]}]})
        self.assertEqual(out["result"]["state"], "failed")

    def test_claimed_success_without_evidence_is_rejected_at_selection(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        with self.assertRaises(TaskError) as cm:
            env.submit(task_id, "gather", {"selected_evidence_ids": ["made-up"], "claimed_success": True})
        self.assertEqual(cm.exception.code, "RESULT_REJECTED")
        # a rejected first action leaves no side effects: still queued, only a rejection event
        self.assertEqual(env.tasks.get_task(agent_ctx(), task_id)["state"], "queued")
        kinds = [e["kind"] for e in env.tasks.get_task_events(agent_ctx(), task_id)["events"]]
        self.assertIn("action_rejected", kinds)

    def test_idempotent_replay_and_conflict(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        k = key()
        a = env.tasks.dispatch_task_action(agent_ctx(), task_id, "search", {"query": "Orion-7 opened"}, k)
        before = env.tasks.store.get_task(task_id)["action_count"]
        b = env.tasks.dispatch_task_action(agent_ctx(), task_id, "search", {"query": "Orion-7 opened"}, k)
        self.assertTrue(b["replayed"])
        self.assertEqual(a["result"]["hop_id"], b["result"]["hop_id"])
        self.assertEqual(env.tasks.store.get_task(task_id)["action_count"], before)
        with self.assertRaises(TaskError) as cm:
            env.tasks.dispatch_task_action(agent_ctx(), task_id, "search", {"query": "something different"}, k)
        self.assertEqual(cm.exception.code, "IDEMPOTENCY_CONFLICT")
        # create_task idempotency
        ik = key()
        t1 = env.tasks.create_task(agent_ctx(), "doc_evidence_check", t1_params(env), idempotency_key=ik)
        t2 = env.tasks.create_task(agent_ctx(), "doc_evidence_check", t1_params(env), idempotency_key=ik)
        self.assertEqual(t1["task_id"], t2["task_id"])
        with self.assertRaises(TaskError):
            env.tasks.create_task(agent_ctx(), "doc_evidence_check",
                                  {**t1_params(env), "questions": [{"field": "x", "question": "y"}]},
                                  idempotency_key=ik)

    def test_state_version_cas_conflict(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        with self.assertRaises(TaskError) as cm:
            env.tasks.dispatch_task_action(agent_ctx(), task_id, "search", {"query": "Orion-7"}, key(),
                                           expected_state_version=999)
        self.assertEqual(cm.exception.code, "TASK_STATE_CONFLICT")

    def test_cancel_and_terminal_rejection(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        env.act(task_id, "search", {"query": "Orion-7 opened"})
        env.tasks.cancel_task(agent_ctx(), task_id, "no longer needed")
        self.assertEqual(env.tasks.get_task(agent_ctx(), task_id)["state"], "cancelled")
        with self.assertRaises(TaskError) as cm:
            env.act(task_id, "search", {"query": "Orion-7 again"})
        self.assertEqual(cm.exception.code, "TASK_INVALID_TRANSITION")
        with self.assertRaises(TaskError):
            env.tasks.cancel_task(agent_ctx(), task_id)

    def test_cancel_during_inflight_action_discards_results(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        env.fault_hook = lambda p: env.tasks.cancel_task(agent_ctx(), task_id) if p == "after_execute" else None
        with self.assertRaises(TaskError) as cm:
            env.act(task_id, "search", {"query": "Orion-7 opened"})
        self.assertEqual(cm.exception.code, "TASK_INVALID_TRANSITION")
        n = env.tasks.store.conn.execute("SELECT COUNT(*) FROM task_evidence WHERE task_id=?", (task_id,)).fetchone()[0]
        self.assertEqual(n, 0)

    def test_approval_revocation_and_param_tamper_block_actions(self) -> None:
        env = self.env
        t1 = env.approved("doc_evidence_check", t1_params(env))
        env.act(t1, "search", {"query": "Orion-7 opened"})
        env.tasks.revoke_task_approval(human_ctx(), t1)
        self.assertEqual(env.tasks.get_task(agent_ctx(), t1)["state"], "cancelled")
        with self.assertRaises(TaskError):
            env.act(t1, "search", {"query": "Orion-7 opened again"})
        t2 = env.approved("doc_evidence_check", t1_params(env))
        env.tasks.store.conn.execute("UPDATE task SET params_sha256='0'*64 WHERE task_id=?".replace("'0'*64", "'" + "0" * 64 + "'"),
                                     (t2,))
        with self.assertRaises(TaskError) as cm:
            env.act(t2, "search", {"query": "Orion-7 opened"})
        self.assertEqual(cm.exception.code, "TASK_AUTH_REVOKED")


class SecurityNegativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(files=CORPUS)

    def tearDown(self) -> None:
        self.env.close()

    def test_cross_principal_and_cross_workspace_access_hidden(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        bob = agent_ctx(BOB)
        for call in (lambda: env.tasks.get_task(bob, task_id),
                     lambda: env.tasks.get_task_events(bob, task_id),
                     lambda: env.tasks.get_task_context(bob, task_id),
                     lambda: env.tasks.dispatch_task_action(bob, task_id, "search", {"query": "x"}, key()),
                     lambda: env.tasks.cancel_task(bob, task_id)):
            with self.assertRaises(TaskError) as cm:
                call()
            self.assertEqual(cm.exception.code, "TASK_NOT_FOUND")
        other_ws = agent_ctx(ALICE, workspace="ffffffff-0000-0000-0000-000000000000")
        with self.assertRaises(TaskError) as cm:
            env.tasks.get_task(other_ws, task_id)
        self.assertEqual(cm.exception.code, "TASK_NOT_FOUND")
        self.assertEqual(env.tasks.list_tasks(bob)["tasks"], [])
        self.assertEqual(len(env.tasks.list_tasks(agent_ctx(is_admin=True))["tasks"]), 1)

    def test_agent_cannot_widen_scope_or_choose_paths(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        for args in ({"query": "x", "source_root_ids": ["other"]}, {"query": "x", "path": "C:/secret"},
                     {"query": "x", "limit": 999}):
            with self.assertRaises(TaskError) as cm:
                env.act(task_id, "search", args)
            self.assertEqual(cm.exception.code, "TASK_VALIDATION_ERROR")
        with self.assertRaises(TaskError) as cm:
            env.tasks.create_task(agent_ctx(), "doc_evidence_check",
                                  {"source_root_ids": ["not-a-root"], **T1_PARAMS})
        self.assertEqual(cm.exception.code, "SOURCE_NOT_AUTHORIZED")
        with self.assertRaises(TaskError) as cm:  # unknown action
            env.act(task_id, "run_shell", {"cmd": "dir"})
        self.assertEqual(cm.exception.code, "ACTION_NOT_ALLOWED")
        with self.assertRaises(TaskError) as cm:  # action not offered by the current step
            env.act(task_id, "write_candidate", {"name": "x.json", "content": "{}"})
        self.assertEqual(cm.exception.code, "ACTION_NOT_ALLOWED")

    def test_events_and_envelope_do_not_leak_queries_text_or_lease_secrets(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        env.act(task_id, "search", {"query": "Session Orion-7 opened by"})
        events = json.dumps(env.tasks.get_task_events(agent_ctx(), task_id)["events"])
        self.assertNotIn("Session Orion-7 opened by", events)
        self.assertNotIn("Maria Lopez", events)
        envelope = json.dumps(env.tasks.get_task(agent_ctx(), task_id)["envelope"])
        for forbidden in ("fencing", "owner_id", "lease", "svc-", "KEY-4242"):
            self.assertNotIn(forbidden, envelope)

    def test_default_security_context_has_no_task_capabilities(self) -> None:
        ctx = SecurityContext(workspace_id=WORKSPACE, principal_id=ALICE)
        self.assertFalse(ctx.can_approve_tasks)
        self.assertFalse(ctx.can_review_tasks)
        self.assertEqual(ctx.actor_kind, "agent")
        with self.assertRaises(TaskError):
            self.env.tasks.review_task_result(ctx, "x", "accept")


class LimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(files=CORPUS)

    def tearDown(self) -> None:
        self.env.close()

    def test_pending_queue_limit(self) -> None:
        with patch.dict(C.LIMITS, {"max_pending_tasks": 2}):
            self.env.create("doc_evidence_check", t1_params(self.env))
            self.env.create("doc_evidence_check", t1_params(self.env))
            with self.assertRaises(TaskError) as cm:
                self.env.create("doc_evidence_check", t1_params(self.env))
            self.assertEqual(cm.exception.code, "TASK_QUEUE_FULL")

    def test_single_active_task_per_workspace(self) -> None:
        env = self.env
        a = env.approved("doc_evidence_check", t1_params(env))
        b = env.approved("doc_evidence_check", t1_params(env))
        env.act(a, "search", {"query": "Orion-7 opened"})
        with self.assertRaises(TaskError) as cm:
            env.act(b, "search", {"query": "Orion-7 opened"})
        self.assertEqual(cm.exception.code, "ACTIVE_TASK_LIMIT")
        self.assertEqual(env.tasks.get_task(agent_ctx(), b)["state"], "queued")

    def test_tool_action_budget(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        with patch.dict(C.LIMITS, {"max_tool_actions": 2}):
            env.act(task_id, "search", {"query": "Orion-7 opened"})
            env.act(task_id, "search", {"query": "Maria Lopez vault"})
            with self.assertRaises(TaskError) as cm:
                env.act(task_id, "search", {"query": "Peter Chen vault"})
            self.assertEqual(cm.exception.code, "ACTION_BUDGET_EXCEEDED")

    def test_wall_clock_deadline_times_out_and_pauses_do_not_count(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        env.act(task_id, "search", {"query": "Orion-7 opened"})
        env.clock.advance(C.LIMITS["task_wall_clock_seconds"] + 5)
        with self.assertRaises(TaskError) as cm:
            env.act(task_id, "search", {"query": "Maria Lopez vault"})
        self.assertEqual(cm.exception.code, "TASK_DEADLINE_EXCEEDED")
        self.assertEqual(env.tasks.get_task(agent_ctx(), task_id)["state"], "timed_out")

    def test_clock_rollback_moves_task_to_review(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        env.act(task_id, "search", {"query": "Orion-7 opened"})
        env.clock.advance(-600)
        with self.assertRaises(TaskError) as cm:
            env.act(task_id, "search", {"query": "Maria Lopez vault"})
        self.assertEqual(cm.exception.code, "CLOCK_UNTRUSTED")
        self.assertEqual(env.tasks.get_task(agent_ctx(), task_id)["state"], "needs_review")

    def test_event_quota_is_bounded(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        with patch.dict(C.LIMITS, {"max_events_per_task": 6}):
            with self.assertRaises(TaskError) as cm:
                for i in range(10):
                    env.act(task_id, "search", {"query": f"Orion-7 opened variant {i}"})
            self.assertEqual(cm.exception.code, "EVENT_QUOTA_EXCEEDED")
        count = env.tasks.store.conn.execute("SELECT COUNT(*) FROM task_event WHERE task_id=?", (task_id,)).fetchone()[0]
        self.assertLessEqual(count, 6 + 16)


class ContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(files=CORPUS)

    def tearDown(self) -> None:
        self.env.close()

    def test_stable_prefix_is_identical_across_tasks_and_calls(self) -> None:
        env = self.env
        a = env.approved("doc_evidence_check", t1_params(env))
        b = env.approved("doc_evidence_check", t1_params(env))
        pa1 = env.tasks.get_task_context(agent_ctx(), a)
        env.clock.advance(30)
        env.act(a, "search", {"query": "Orion-7 opened"})
        pa2 = env.tasks.get_task_context(agent_ctx(), a)
        pb = env.tasks.get_task_context(agent_ctx(), b)
        self.assertEqual(pa1["prefix_sha256"], pa2["prefix_sha256"])
        self.assertEqual(pa1["prefix_sha256"], pb["prefix_sha256"])
        # the only identifier allowed in the prefix is the caller-declared source root (stable per task)
        prefix_text = json.dumps(pa1["prefix"], sort_keys=True).replace(env.root_id, "<root>")
        self.assertFalse(re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", prefix_text))
        self.assertFalse(re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:", prefix_text))
        self.assertNotIn("attempt", prefix_text)
        # volatile part comes after the prefix in serialization order
        self.assertEqual(list(pa1)[:3], ["prefix", "prefix_sha256", "volatile"])
        self.assertLessEqual(pa2["context_bytes"], C.LIMITS["context_packet_bytes"])

    def test_action_schemas_use_only_conservative_subset(self) -> None:
        from pdx_local_ai.tasks.templates import ACTION_SCHEMAS
        allowed = {"type", "properties", "required", "enum", "minLength", "maxLength", "minimum", "maximum",
                   "additionalProperties", "items"}

        def walk(node: object) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    if k != "properties":
                        self.assertIn(k, allowed, k)
                    if k == "properties":
                        for sub in v.values():
                            walk(sub)
                    else:
                        walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        for name, schema in ACTION_SCHEMAS.items():
            walk(schema)
            self.assertIs(schema["additionalProperties"], False, name)

    def test_envelope_is_deterministic_minimal_and_bounded(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        e1 = env.tasks.get_task(agent_ctx(), task_id)["envelope"]
        e2 = env.tasks.get_task(agent_ctx(), task_id)["envelope"]
        self.assertEqual(json.dumps(e1, sort_keys=True), json.dumps(e2, sort_keys=True))
        self.assertEqual(e1["available_actions"], ["search", "submit_step"])
        self.assertEqual(e1["remaining"]["tool_actions"], C.LIMITS["max_tool_actions"])
        self.assertLess(len(json.dumps(e1)), 4096)

    def test_critical_context_never_silently_truncated(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        with patch.dict(C.LIMITS, {"context_packet_bytes": 600}):
            with self.assertRaises(TaskError) as cm:
                env.tasks.get_task_context(agent_ctx(), task_id)
        self.assertEqual(cm.exception.code, "CONTEXT_BUDGET_EXCEEDED")

    def test_noncritical_evidence_windows_are_dropped_with_references(self) -> None:
        env = Env(files={f"f{i}.txt": ("alpha " * 300 + f" unique{i}") for i in range(6)})
        try:
            task_id = env.approved("doc_evidence_check", {"source_root_ids": [env.root_id], **T1_PARAMS},
                                   context_mode="bounded_full")
            env.act(task_id, "search", {"query": "alpha"})
            with patch.dict(C.LIMITS, {"context_packet_bytes": 6000}):
                packet = env.tasks.get_task_context(agent_ctx(), task_id)
            self.assertGreater(packet["volatile"]["omitted_count"], 0)
            self.assertLessEqual(packet["context_bytes"], 6000)
            row = env.tasks.store.conn.execute(
                "SELECT omitted_count FROM task_context_measurement WHERE task_id=?", (task_id,)).fetchone()
            self.assertEqual(row[0], packet["volatile"]["omitted_count"])
        finally:
            env.close()

    def test_context_read_records_one_measurement_and_keeps_the_event_log(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        before_events = env.tasks.store.conn.execute(
            "SELECT COUNT(*) FROM task_event WHERE task_id=?", (task_id,)).fetchone()[0]
        before_version = env.tasks.get_task(agent_ctx(), task_id)["state_version"]
        first = env.tasks.get_task_context(agent_ctx(), task_id)
        second = env.tasks.get_task_context(agent_ctx(), task_id)
        after_events = env.tasks.store.conn.execute(
            "SELECT COUNT(*) FROM task_event WHERE task_id=?", (task_id,)).fetchone()[0]
        self.assertEqual(before_events, after_events)
        self.assertEqual(env.tasks.get_task(agent_ctx(), task_id)["state_version"], before_version)
        rows = env.tasks.store.conn.execute(
            "SELECT * FROM task_context_measurement WHERE task_id=?", (task_id,)).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["context_sha256"], first["context_sha256"])
        self.assertEqual(rows[0]["prefix_sha256"], second["prefix_sha256"])
        self.assertEqual(rows[0]["task_state"], "queued")
        self.assertIsNone(rows[0]["measurement_error"])
        self.assertEqual(rows[0]["evidence_window_bytes"],
                         sum(len(item["text"].encode("utf-8")) for item in first["volatile"]["evidence_windows"]))
        expected = env.catalog.conn.execute(
            """SELECT COALESCE(SUM(sv.size_bytes), 0)
               FROM file_record f
               JOIN source_version sv ON sv.source_version_id = f.current_source_version_id
               JOIN file_acl a ON a.file_record_id = f.file_record_id AND a.workspace_id = f.workspace_id
               WHERE f.workspace_id=? AND a.principal_id=? AND a.can_read=1
                 AND f.catalog_status='active' AND f.source_root_id=?""",
            (WORKSPACE, ALICE, env.root_id)).fetchone()[0]
        self.assertEqual(rows[0]["eligible_file_bytes"], expected)
        self.assertGreater(expected, 0)
        self.assertEqual(rows[0]["ledger_queries"], 0)
        self.assertEqual(rows[0]["hop_count"], 0)
        self.assertIsNone(rows[0]["retrieval_terminal_reason"])
        self.assertIsNotNone(rows[0]["ledger_remaining_json"])

    def test_search_fills_retrieval_reason_and_ledger_counts(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        env.act(task_id, "search", {"query": "Orion-7 opened"})
        packet = env.tasks.get_task_context(agent_ctx(), task_id)
        row = env.tasks.store.conn.execute(
            """SELECT retrieval_terminal_reason, ledger_queries, hop_count, ledger_remaining_json
               FROM task_context_measurement WHERE context_sha256=?""",
            (packet["context_sha256"],)).fetchone()
        hop = env.tasks.store.conn.execute(
            "SELECT stop_reason, status FROM task_hop WHERE task_id=? ORDER BY hop_no DESC LIMIT 1",
            (task_id,)).fetchone()
        self.assertEqual(row["retrieval_terminal_reason"], hop["stop_reason"] or hop["status"])
        self.assertEqual(row["hop_count"], 1)
        self.assertEqual(row["ledger_queries"], 1)
        self.assertIn("queries", row["ledger_remaining_json"])

    def test_same_context_hash_keeps_the_first_hop_snapshot(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        first = env.tasks.get_task_context(agent_ctx(), task_id)
        env.act(task_id, "search", {"query": "Orion-7 opened"})
        second = env.tasks.get_task_context(agent_ctx(), task_id)
        third = env.tasks.get_task_context(agent_ctx(), task_id)
        self.assertNotEqual(first["context_sha256"], second["context_sha256"])
        self.assertEqual(second["context_sha256"], third["context_sha256"])
        rows = env.tasks.store.conn.execute(
            """SELECT context_sha256, hop_count, ledger_queries, retrieval_terminal_reason
               FROM task_context_measurement WHERE task_id=?""",
            (task_id,)).fetchall()
        by_hash = {row["context_sha256"]: row for row in rows}
        self.assertEqual(len(rows), 2)
        self.assertEqual(by_hash[first["context_sha256"]]["hop_count"], 0)
        self.assertEqual(by_hash[first["context_sha256"]]["ledger_queries"], 0)
        self.assertIsNone(by_hash[first["context_sha256"]]["retrieval_terminal_reason"])
        self.assertEqual(by_hash[second["context_sha256"]]["hop_count"], 1)
        self.assertEqual(by_hash[second["context_sha256"]]["ledger_queries"], 1)

    def test_measurement_check_failure_is_not_ignored(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        packet = env.tasks.get_task_context(agent_ctx(), task_id)
        task = dict(env.tasks.store.conn.execute("SELECT * FROM task WHERE task_id=?", (task_id,)).fetchone())
        task["state"] = "succeeded"
        attempt = env.tasks.store.conn.execute(
            "SELECT * FROM task_attempt WHERE task_id=?", (task_id,)).fetchone()
        packet = dict(packet)
        packet["context_sha256"] = "ab" * 32
        before = env.tasks.store.conn.execute(
            "SELECT COUNT(*) FROM task_context_measurement WHERE task_id=?", (task_id,)).fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            env.tasks._record_context_measurement(env.tasks.store.conn, task, attempt, attempt["step_id"], None, packet)
        after = env.tasks.store.conn.execute(
            "SELECT COUNT(*) FROM task_context_measurement WHERE task_id=?", (task_id,)).fetchone()[0]
        self.assertEqual(after, before)

    def test_measurement_write_failure_still_returns_the_packet(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))

        def boom(*_args, **_kwargs):
            raise RuntimeError(r"D:\private\tasks.sqlite")

        with patch.object(env.tasks, "_record_context_measurement", boom):
            packet = env.tasks.get_task_context(agent_ctx(), task_id)
        self.assertIn("prefix_sha256", packet)
        self.assertNotIn("private", json.dumps(packet))

    def test_catalog_read_failure_records_only_an_error_code(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))

        class BrokenCatalog:
            class _Conn:
                def execute(self, *_args, **_kwargs):
                    raise sqlite3.OperationalError(r"D:\private\catalog.sqlite")

            conn = _Conn()

        env.tasks.search.agent_service.catalog = BrokenCatalog()
        packet = env.tasks.get_task_context(agent_ctx(), task_id)
        self.assertIn("prefix_sha256", packet)
        row = env.tasks.store.conn.execute(
            "SELECT eligible_file_bytes, measurement_error FROM task_context_measurement WHERE task_id=?",
            (task_id,)).fetchone()
        self.assertIsNone(row[0])
        self.assertEqual(row[1], "CATALOG_READ_FAILED")

    def test_budget_exceeded_writes_no_measurement(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", t1_params(env))
        with patch.dict(C.LIMITS, {"context_packet_bytes": 600}):
            with self.assertRaises(TaskError) as cm:
                env.tasks.get_task_context(agent_ctx(), task_id)
        self.assertEqual(cm.exception.code, "CONTEXT_BUDGET_EXCEEDED")
        count = env.tasks.store.conn.execute(
            "SELECT COUNT(*) FROM task_context_measurement WHERE task_id=?", (task_id,)).fetchone()[0]
        self.assertEqual(count, 0)


def _mode_sources() -> dict[str, str]:
    """Sixteen raw files. The total is above 64 KiB, and neither group is an answer key."""
    padding = "notes " * 1250
    files = {f"a{i:02d}.txt": f"orionbatch {padding}" for i in range(8)}
    files.update({f"b{i:02d}.txt": f"vegabatch {padding}" for i in range(8)})
    return files


class ModeByteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(files=_mode_sources())

    def tearDown(self) -> None:
        self.env.close()

    def _packet(self, task_id: str) -> dict:
        packet = self.env.tasks.get_task_context(agent_ctx(), task_id)
        row = self.env.tasks.store.conn.execute(
            """SELECT context_mode, context_bytes, eligible_file_bytes, evidence_window_count, omitted_count
               FROM task_context_measurement WHERE task_id=? AND context_sha256=?""",
            (task_id, packet["context_sha256"])).fetchone()
        evidence = self.env.tasks.store.conn.execute(
            "SELECT COUNT(*) FROM task_evidence WHERE task_id=?", (task_id,)).fetchone()[0]
        self.assertIsNotNone(row["eligible_file_bytes"])
        self.assertGreater(row["eligible_file_bytes"], C.LIMITS["context_packet_bytes"])
        self.assertEqual(row["context_bytes"], packet["context_bytes"])
        self.assertLessEqual(packet["context_bytes"], C.LIMITS["context_packet_bytes"])
        self.assertEqual(row["evidence_window_count"], len(packet["volatile"]["evidence_windows"]))
        self.assertEqual(row["omitted_count"], packet["volatile"]["omitted_count"])
        window_bytes = sum(len(item["text"].encode("utf-8")) for item in packet["volatile"]["evidence_windows"])
        self.assertLess(window_bytes, row["eligible_file_bytes"])
        return {"packet": packet, "row": row, "evidence": evidence}

    def test_retrieval_omits_by_window_count(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", {"source_root_ids": [env.root_id], **T1_PARAMS})
        env.act(task_id, "search", {"query": "orionbatch"})
        env.act(task_id, "search", {"query": "vegabatch"})
        measured = self._packet(task_id)
        self.assertEqual(measured["row"]["context_mode"], "bounded_retrieval")
        self.assertGreater(measured["evidence"], 8)
        self.assertEqual(len(measured["packet"]["volatile"]["evidence_windows"]), 8)
        self.assertEqual(measured["packet"]["volatile"]["omitted_count"], measured["evidence"] - 8)

    def test_multihop_omits_by_window_count(self) -> None:
        env = self.env
        task_id = env.approved("multihop_trace", {
            "source_root_ids": [env.root_id], "start_entity": "orionbatch", "target_relation": "notes"})
        env.act(task_id, "search", {"query": "orionbatch"})
        measured = self._packet(task_id)
        self.assertEqual(measured["row"]["context_mode"], "bounded_multihop")
        self.assertGreater(measured["evidence"], 6)
        self.assertEqual(len(measured["packet"]["volatile"]["evidence_windows"]), 6)
        self.assertEqual(measured["packet"]["volatile"]["omitted_count"], measured["evidence"] - 6)

    def test_full_drops_windows_for_the_byte_budget(self) -> None:
        env = self.env
        task_id = env.approved("doc_evidence_check", {"source_root_ids": [env.root_id], **T1_PARAMS},
                               context_mode="bounded_full")
        env.act(task_id, "search", {"query": "orionbatch"})
        env.act(task_id, "search", {"query": "vegabatch"})
        measured = self._packet(task_id)
        self.assertEqual(measured["row"]["context_mode"], "bounded_full")
        self.assertLessEqual(measured["evidence"], 64)
        self.assertGreater(measured["evidence"], 0)
        windows = len(measured["packet"]["volatile"]["evidence_windows"])
        self.assertLess(windows, measured["evidence"])
        self.assertEqual(measured["packet"]["volatile"]["omitted_count"], measured["evidence"] - windows)

    def test_three_modes_share_one_eligible_total(self) -> None:
        env = self.env
        expected = env.catalog.conn.execute(
            """SELECT COALESCE(SUM(sv.size_bytes), 0), COUNT(*)
               FROM file_record f
               JOIN source_version sv ON sv.source_version_id = f.current_source_version_id
               JOIN file_acl a ON a.file_record_id = f.file_record_id AND a.workspace_id = f.workspace_id
               WHERE f.workspace_id=? AND a.principal_id=? AND a.can_read=1
                 AND f.catalog_status='active' AND f.source_root_id=?""",
            (WORKSPACE, ALICE, env.root_id)).fetchone()
        self.assertEqual(expected[1], 16)
        self.assertGreater(expected[0], C.LIMITS["context_packet_bytes"])
        retrieval = env.approved("doc_evidence_check", {"source_root_ids": [env.root_id], **T1_PARAMS})
        env.act(retrieval, "search", {"query": "orionbatch"})
        env.act(retrieval, "search", {"query": "vegabatch"})
        retrieval_measured = self._packet(retrieval)
        env.tasks.cancel_task(agent_ctx(), retrieval)
        full = env.approved("doc_evidence_check", {"source_root_ids": [env.root_id], **T1_PARAMS},
                            context_mode="bounded_full")
        env.act(full, "search", {"query": "orionbatch"})
        env.act(full, "search", {"query": "vegabatch"})
        full_measured = self._packet(full)
        env.tasks.cancel_task(agent_ctx(), full)
        multihop = env.approved("multihop_trace", {
            "source_root_ids": [env.root_id], "start_entity": "orionbatch", "target_relation": "notes"})
        env.act(multihop, "search", {"query": "orionbatch"})
        multihop_measured = self._packet(multihop)
        totals = [retrieval_measured["row"]["eligible_file_bytes"],
                  full_measured["row"]["eligible_file_bytes"],
                  multihop_measured["row"]["eligible_file_bytes"]]
        self.assertEqual(totals, [expected[0], expected[0], expected[0]])
        self.assertLess(multihop_measured["evidence"], retrieval_measured["evidence"])
        self.assertLess(multihop_measured["evidence"], 16)


class ScriptedDriverTests(unittest.TestCase):
    def test_multihop_trace_succeeds_from_packet_text_only(self) -> None:
        start = "s" + key().split("-", 1)[1][:12]
        mid = "m" + key().split("-", 1)[1][:12]
        answer = "a" + key().split("-", 1)[1][:12]
        env = Env(files={
            "a.txt": f"{start} opens the record. [[next {mid}]]",
            "b.txt": f"{mid} holds the record. [[answer {answer}]]",
        })
        try:
            task_id = env.approved("multihop_trace", {
                "source_root_ids": [env.root_id], "start_entity": start,
                "target_relation": "record", "max_hops": 3})
            scripted_multihop_driver(env.tasks, agent_ctx(), task_id)
            task = env.tasks.get_task(agent_ctx(), task_id)
            self.assertEqual(task["state"], "succeeded")
            report = env.tasks.store.conn.execute(
                "SELECT artifact_json FROM task_attempt WHERE task_id=? AND step_id='report'",
                (task_id,)).fetchone()
            self.assertEqual(json.loads(report[0])["answer"], answer)
            rows = env.tasks.store.conn.execute(
                """SELECT hop_count, ledger_queries, task_state, provider_name,
                          provider_input_tokens, provider_output_tokens, measurement_error
                   FROM task_context_measurement WHERE task_id=?""",
                (task_id,)).fetchall()
            self.assertGreaterEqual(max(row["hop_count"] for row in rows), 2)
            self.assertGreaterEqual(max(row["ledger_queries"] for row in rows), 2)
            self.assertTrue({row["task_state"] for row in rows} <= {"queued", "running"})
            self.assertTrue(all(row["provider_name"] is None and row["provider_input_tokens"] is None
                                and row["provider_output_tokens"] is None and row["measurement_error"] is None
                                for row in rows))
        finally:
            env.close()


class PublishedMemoryTests(unittest.TestCase):
    def test_pending_l2_is_empty_and_published_l2_is_separate_from_l1(self) -> None:
        from pdx_local_ai.governed_memory import (
            publish_approved_proposal,
            record_human_decision,
            request_publication,
        )
        env = Env(files={"m.txt": "memmark\nviolet-token\n"})
        try:
            params = {
                "source_root_ids": [env.root_id],
                "instruction": "Read memmark",
                "memory_scope_id": "scope1",
                "output_schema": {"type": "object", "properties": {"summary": {"type": "string"}},
                                  "required": ["summary"], "additionalProperties": False},
            }
            task_id = env.approved("doc_memory_artifact", params)
            found = env.act(task_id, "search", {"query": "memmark"})
            citation_id = found["result"]["evidence"][0]["citation_id"]
            state = env.tasks.memory.propose(
                workspace_id=WORKSPACE, principal_id=ALICE, task_id=task_id, scope_id="scope1",
                content="memmark\nviolet-token", citation_id=citation_id, state={},
                on_progress=lambda _state: None,
            )
            pending = env.act(task_id, "recall_published_memory", {"query": "memmark"})
            self.assertEqual(pending["result"]["items"], [])
            self.assertEqual(pending["result"]["layer"], "l2")
            decision = record_human_decision(
                env.catalog.conn, workspace_id=WORKSPACE, principal_id=ALICE,
                proposal_id=state["proposal_id"], reviewer_actor_id="human-reviewer",
                decision="approve", selected_disposition="novel", idempotency_key=key(),
            )
            request = request_publication(
                env.catalog.conn, workspace_id=WORKSPACE, principal_id=ALICE,
                proposal_id=state["proposal_id"], decision_id=decision["decision_id"],
                requesting_actor_id="human-reviewer", idempotency_key=key(),
            )
            receipt = publish_approved_proposal(
                env.catalog.conn, workspace_id=WORKSPACE, principal_id=ALICE,
                publication_request_id=request["publication_request_id"], idempotency_key=key(),
            )
            self.assertEqual(receipt["terminal_result"], "published_new")
            published = env.act(task_id, "recall_published_memory", {"query": "memmark"})
            self.assertTrue(any(
                item["layer"] == "l2" and item["approval"] == "published" and "violet-token" in item["content"]
                for item in published["result"]["items"]
            ))
            l1 = env.act(task_id, "recall_memory", {})
            l1_ids = {item["memory_id"] for item in l1["result"]["items"]}
            l2_ids = {item["memory_id"] for item in published["result"]["items"]}
            self.assertTrue(l1_ids)
            self.assertTrue(l2_ids.isdisjoint(l1_ids))
            self.assertTrue(all(item.get("layer") != "l2" for item in l1["result"]["items"]))
        finally:
            env.close()

    def test_model_view_renders_windows_without_a_directory_path(self) -> None:
        from pdx_local_ai.tasks.model_view import render_model_view
        packet = {"volatile": {
            "hops": [{"hop_id": "h1", "entity": "hop1ent"}],
            "evidence_windows": [{
                "hop_id": "h1",
                "citation_id": "cite-1",
                "source_version_id": r"D:\secret\root",
                "text": "answer line",
            }],
        }}
        text = render_model_view(packet)
        self.assertIn("answer line", text)
        self.assertIn("citation_id: cite-1", text)
        self.assertIn("entity: hop1ent", text)
        self.assertNotIn(r"D:\secret\root", text)
        self.assertNotIn("source_version_id: D:", text)


class MemoryHopDeliveryTests(unittest.TestCase):
    def test_memory_user_message_keeps_the_question_and_rejects_only_shape(self) -> None:
        from pdx_local_ai.tasks.memory_turn import MEMORY_USER_NOTE, memory_user_message
        question = "見 https://example.test/a 與 C:\\notes 以及 /tmp。"
        text = memory_user_message(question)
        self.assertEqual(text, MEMORY_USER_NOTE + "\n" + question)
        self.assertEqual(
            MEMORY_USER_NOTE,
            "已發布筆記不在這則訊息裡，只能經由工具 recall_published_memory 取得。",
        )
        self.assertIn("https://example.test/a", text)
        self.assertEqual(memory_user_message(" "), "已發布筆記不在這則訊息裡，只能經由工具 recall_published_memory 取得。\n ")
        for bad in ("", "x" * 501, None, 12):
            with self.assertRaises(ValueError):
                memory_user_message(bad)  # type: ignore[arg-type]

    def test_memory_tool_result_keeps_published_l2_only(self) -> None:
        from pdx_local_ai.tasks.memory_turn import memory_tool_result, memory_user_message
        token = "violet-token"
        text = memory_tool_result([
            {"layer": "l1", "approval": "published", "content": token},
            {"layer": "l2", "approval": "pending", "content": token},
            {"layer": "l2", "approval": "published", "content": 5},
            {"layer": "l2", "approval": "published", "content": "memmark\n" + token},
            "not-a-dict",
        ])
        self.assertEqual(text, "layer: l2\napproval: published\nmemmark\n" + token)
        self.assertNotIn(token, memory_user_message("memmark 下一行的值是什麼"))
        self.assertEqual(memory_tool_result([]), "")
        self.assertEqual(memory_tool_result(None), "")  # type: ignore[arg-type]

    def test_hop_chain_orders_parents_and_survives_a_broken_packet(self) -> None:
        from pdx_local_ai.tasks.model_view import render_hop_chain, render_model_view
        packet = {"volatile": {
            "hops": [
                {"hop_id": "h2", "hop_no": 2, "parent_hop_id": "h1", "entity": "lnk"},
                {"hop_id": "h1", "hop_no": True, "parent_hop_id": None, "entity": "hop1ent"},
                {"hop_no": "nope", "entity": r"D:\secret\root"},
            ],
            "evidence_windows": [
                {"hop_id": "h2", "text": "answer line"},
                {"hop_id": "h1", "citation_id": "cite-1", "source_version_id": r"D:\secret\root", "text": "start line"},
                {"hop_id": "h2", "text": "second window"},
            ],
        }}
        text = render_hop_chain(packet)
        self.assertLess(text.index("entity: hop1ent"), text.index("entity: lnk"))
        self.assertIn("hop_no: 0\nparent_entity: \nentity: hop1ent\nstart line", text)
        self.assertIn("hop_no: 2\nparent_entity: hop1ent\nentity: lnk\nanswer line\nsecond window", text)
        self.assertNotIn(r"D:\secret\root", text.split("entity: lnk")[0])
        self.assertIn("start line", text)
        self.assertEqual(render_hop_chain({"volatile": {}}), "")
        self.assertIsInstance(render_hop_chain({"volatile": {"hops": [{"entity": "only"}]}}), str)
        plain = render_model_view(packet)
        self.assertIn("start line", plain)
        self.assertIn("entity: hop1ent", plain)


if __name__ == "__main__":
    unittest.main()
