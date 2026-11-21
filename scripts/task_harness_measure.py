"""Task harness utility measurements (plan section 9.1).

Usage: python scripts/task_harness_measure.py --out <new-empty-dir>
Writes raw per-trial JSONL plus measurements.json. Never overwrites an existing output directory.
Inference-level measurements (prefill/decode timing, structured-output compliance) need a local
inference engine and are reported as `not_measured` here; they are not simulated.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "tests"))
sys.path.insert(0, str(_ROOT / "src"))

from task_harness_support import Env, FakeClock, agent_ctx, human_ctx, key  # noqa: E402

from pdx_local_ai.service.contracts import AgentSearchRequest  # noqa: E402
from pdx_local_ai.tasks.context import RetrievalLedger  # noqa: E402

FIRST = ["Maria", "Peter", "Ana", "Jonas", "Lena", "Omar", "Yuki", "Hana", "Ravi", "Tomas"]
LAST = ["Lopez", "Chen", "Silva", "Berg", "Novak", "Haddad", "Sato", "Kim", "Rao", "Weber"]
T1 = [{"field": "opener", "question": "Who opened the session?"}]


def pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(p * len(ordered)))], 3)


def corpus(n: int) -> dict[str, str]:
    files: dict[str, str] = {}
    for i in range(n):
        person = f"{FIRST[i % 10]} {LAST[(i // 10 + i) % 10]}{'abcdefghij'[i // 10]}"
        files[f"s{i:02d}.txt"] = f"Session ORION-{i} was opened by {person} on cluster east{i}."
        files[f"k{i:02d}.txt"] = f"{person} owns vault key KEY-{1000 + i} for release train {i}."
    for j in range(10):
        files[f"x{j:02d}.txt"] = f"Cafeteria notice {j}: soup and bread are served on weekday {j}."
    return files


def person_of(text: str) -> str:
    return text.split(" opened by ", 1)[1].split(" on ", 1)[0]


def measure_overhead(out: Path, trials: int) -> dict:
    env = Env(files={"a.txt": "Session Orion-7 was opened by Maria Lopez on the east cluster."},
              clock=FakeClock(time.time()))
    rows = []
    try:
        for i in range(trials):
            task_id = env.approved("doc_evidence_check", {"source_root_ids": [env.root_id], "questions": T1})
            t0 = time.perf_counter()
            env.agent.search_documents(AgentSearchRequest(
                workspace_id=agent_ctx().workspace_id, principal_id="alice", source_root_ids=[env.root_id],
                query="Session Orion-7 opened by", timeout_ms=3000, limit=8, opened_files=24, opened_blocks=48,
                returned_bytes=60000, metadata_candidates=100, lexical_candidates=100),
                context=agent_ctx(), search_mode="background_refresh")
            direct = (time.perf_counter() - t0) * 1000
            t1 = time.perf_counter()
            env.act(task_id, "search", {"query": "Session Orion-7 opened by"})
            via = (time.perf_counter() - t1) * 1000
            env.tasks.cancel_task(agent_ctx(), task_id, "measurement done")  # one active task per workspace
            rows.append({"trial": i, "direct_ms": round(direct, 3), "via_task_ms": round(via, 3),
                         "overhead_ms": round(via - direct, 3)})
    finally:
        env.close()
    (out / "overhead.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    ov = [r["overhead_ms"] for r in rows]
    return {"trials": trials, "direct_ms_median": pct([r["direct_ms"] for r in rows], 0.5),
            "via_task_ms_median": pct([r["via_task_ms"] for r in rows], 0.5),
            "overhead_ms_median": pct(ov, 0.5), "overhead_ms_p95": pct(ov, 0.95)}


def measure_recovery(out: Path, trials: int) -> dict:
    rows = []
    for i in range(trials):
        env = Env(files={"a.txt": "Session Orion-7 was opened by Maria Lopez on the east cluster."},
                  clock=FakeClock(time.time()))
        try:
            task_id = env.approved("doc_evidence_check", {"source_root_ids": [env.root_id], "questions": T1})
            point = ("after_intent", "after_execute")[i % 2]
            k = key()

            def hook(p: str, point: str = point) -> None:
                if p == point:
                    raise RuntimeError("simulated crash")
            env.fault_hook = hook
            try:
                env.tasks.dispatch_task_action(agent_ctx(), task_id, "search", {"query": "Session Orion-7 opened by"}, k)
            except RuntimeError:
                pass
            env.fault_hook = None
            env.clock.advance(150)
            svc = env.new_service()
            svc.recover()
            svc.resume_task(agent_ctx(), task_id)
            res = svc.dispatch_task_action(agent_ctx(), task_id, "search", {"query": "Session Orion-7 opened by"}, k)
            eid = res["result"]["evidence"][0]["evidence_id"]
            svc.submit_task_result(agent_ctx(), task_id, "gather", {"selected_evidence_ids": [eid]}, key())
            fin = svc.submit_task_result(agent_ctx(), task_id, "report", {"items": [
                {"field": "opener", "value": "Maria Lopez", "evidence_ids": [eid]}]}, key())
            hops = svc.store.conn.execute("SELECT COUNT(*) FROM task_hop WHERE task_id=?", (task_id,)).fetchone()[0]
            rows.append({"trial": i, "crash_point": point, "state": fin["result"]["state"], "duplicate_effects": hops != 1})
        finally:
            env.close()
    (out / "recovery.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    ok = sum(1 for r in rows if r["state"] == "succeeded" and not r["duplicate_effects"])
    return {"trials": trials, "recovered_without_duplicates": ok, "success_rate": round(ok / trials, 3)}


def measure_rework_and_context(out: Path) -> dict:
    env = Env(files={"a.txt": "Session Orion-7 was opened by Maria Lopez on the east cluster."},
              clock=FakeClock(time.time()))
    try:
        params = {"source_root_ids": [env.root_id], "questions": T1}
        task_id = env.approved("doc_evidence_check", params)
        env.act(task_id, "search", {"query": "Session Orion-7 opened by"})
        ev = env.tasks.store.conn.execute("SELECT evidence_id FROM task_evidence WHERE task_id=?", (task_id,)).fetchone()[0]
        env.submit(task_id, "gather", {"selected_evidence_ids": [ev]})
        bad = env.submit(task_id, "report", {"items": [{"field": "opener", "value": "Wrong", "evidence_ids": [ev]}]})
        assert bad["result"]["state"] == "needs_review"
        env.tasks.review_task_result(human_ctx(), task_id, "rework", step_id="report", note="fix")
        ctx_rework = env.tasks.get_task_context(agent_ctx(), task_id)
        env.submit(task_id, "report", {"items": [{"field": "opener", "value": "Maria Lopez", "evidence_ids": [ev]}]})
        final = env.tasks.get_task(agent_ctx(), task_id)["state"]
        # Context packet stability: same params in a second task share an identical prefix hash.
        t2 = env.approved("doc_evidence_check", params)
        packets = [env.tasks.get_task_context(agent_ctx(), t2) for _ in range(5)]
        env.tasks.cancel_task(agent_ctx(), t2, "next")
        task_a = env.approved("doc_evidence_check", params)
        pa = env.tasks.get_task_context(agent_ctx(), task_a)
        sizes = {"context_bytes": pa["context_bytes"], "prefix_bytes": len(json.dumps(pa["prefix"], sort_keys=True).encode())}
        return {
            "rework": {"final_state": final, "tool_calls_partial_rework": 1, "tool_calls_full_restart": 3,
                       "reused_upstream_artifacts": 1, "rework_note_in_context": ctx_rework["volatile"].get("rework_note")},
            "context": {**sizes, "prefix_ratio": round(sizes["prefix_bytes"] / max(1, sizes["context_bytes"]), 3),
                        "prefix_identical_across_calls": len({p["prefix_sha256"] for p in packets}) == 1,
                        "prefix_identical_across_tasks": pa["prefix_sha256"] == packets[0]["prefix_sha256"],
                        "limit_bytes": 65536},
        }
    finally:
        env.close()


def measure_multihop(out: Path, chains: int) -> dict:
    files = corpus(chains)
    env = Env(files=files, clock=FakeClock(time.time()))
    rows, max_ratio = [], 0.0
    try:
        for i in range(chains):
            # --- single-shot baseline: one query, ask for the key directly
            task_s = env.approved("doc_evidence_check", {"source_root_ids": [env.root_id], "questions": T1})
            single = env.act(task_s, "search", {"query": f"vault key for session ORION-{i}"})
            single_hit = any(f"KEY-{1000 + i}" in e["text"] for e in single["result"]["evidence"])
            single_bytes = sum(len(e["text"]) for e in single["result"]["evidence"])
            env.tasks.cancel_task(agent_ctx(), task_s, "baseline done")
            # --- bounded multihop
            task_id = env.approved("multihop_trace", {"source_root_ids": [env.root_id], "start_entity": f"ORION-{i}",
                                                      "target_relation": "vault key of the session opener"})
            r1 = env.act(task_id, "search", {"query": f"Session ORION-{i} opened by"})
            ev1 = next(e for e in r1["result"]["evidence"] if f"ORION-{i} " in e["text"])
            person = person_of(ev1["text"])
            r2 = env.act(task_id, "search", {"query": f"{person} vault key", "parent_hop_id": r1["result"]["hop_id"],
                                             "entity": person})
            ev2 = next((e for e in r2["result"]["evidence"] if f"KEY-{1000 + i}" in e["text"]), None)
            state, queries = "no_evidence", 2
            if ev2 is not None:
                chain = [{"hop_id": r1["result"]["hop_id"], "entity": f"ORION-{i}", "evidence_ids": [ev1["evidence_id"]]},
                         {"hop_id": r2["result"]["hop_id"], "entity": person, "evidence_ids": [ev2["evidence_id"]]}]
                sub = env.submit(task_id, "trace", {"chain": chain, "answer": f"KEY-{1000 + i}"})
                fin = env.submit(task_id, "report", {"answer": f"KEY-{1000 + i}",
                                                     "trace_sha256": sub["result"]["artifact_sha256"]})
                state = fin["result"]["state"]
            attempt = env.tasks.store.conn.execute(
                "SELECT current_attempt_id FROM task_step WHERE task_id=? AND step_id='trace'", (task_id,)).fetchone()[0]
            led = RetrievalLedger.load(env.tasks.store.conn, task_id, attempt)
            ratios = [led.data["consumed"][k] / max(1, led.data["limits"][k]) for k in led.data["limits"]]
            max_ratio = max(max_ratio, max(ratios))
            if state != "succeeded":
                env.tasks.cancel_task(agent_ctx(), task_id, "chain not completed")
            rows.append({"chain": i, "single_shot_found": single_hit, "single_shot_bytes": single_bytes,
                         "multihop_state": state, "multihop_queries": queries, "max_ledger_ratio": round(max(ratios), 4)})
    finally:
        env.close()
    (out / "multihop.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return {"chains": chains, "single_shot_success": sum(r["single_shot_found"] for r in rows),
            "multihop_success": sum(r["multihop_state"] == "succeeded" for r in rows),
            "ledger_max_consumed_ratio": round(max_ratio, 4), "ledger_never_overrun": max_ratio <= 1.0,
            "corpus_files": len(files)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--overhead-trials", type=int, default=25)
    ap.add_argument("--recovery-trials", type=int, default=20)
    ap.add_argument("--chains", type=int, default=20)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=False)  # never overwrite an earlier record
    result = {
        "schema": "pdx_task_harness_measurements_v1",
        "control_plane_overhead": measure_overhead(out, a.overhead_trials),
        "recovery": measure_recovery(out, a.recovery_trials),
        "rework_and_context": measure_rework_and_context(out),
        "multihop_vs_single_shot": measure_multihop(out, a.chains),
        "not_measured": {"prefill_decode_timing": "requires local inference engine",
                         "structured_output_compliance": "requires local inference engine"},
        "note": "synthetic corpus; scripted agent; results are utility measurements, not model-quality claims",
    }
    (out / "measurements.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


_ = statistics

if __name__ == "__main__":
    raise SystemExit(main())
