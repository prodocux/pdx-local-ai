"""Worker functions for multi-process lease/CAS races (spawn-safe, importable)."""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def race_lease(db_path: str, task_id: str, owner: str, barrier, queue) -> None:  # noqa: ANN001
    from pdx_local_ai.tasks.contracts import TaskError
    from pdx_local_ai.tasks.store import TaskStore
    store = TaskStore(db_path)
    barrier.wait(timeout=30)
    try:
        with store.tx() as conn:
            token = store.acquire_lease(conn, task_id, owner)
        queue.put((owner, "ok", token))
    except TaskError as exc:
        queue.put((owner, exc.code, None))
    finally:
        store.close()


def race_cas(db_path: str, task_id: str, expected: int, barrier, queue, tag: str) -> None:  # noqa: ANN001
    from pdx_local_ai.tasks.contracts import TaskError
    from pdx_local_ai.tasks.store import TaskStore
    store = TaskStore(db_path)
    barrier.wait(timeout=30)
    try:
        with store.tx() as conn:
            store.cas_state(conn, task_id, expected, "queued")
        queue.put((tag, "ok"))
    except TaskError as exc:
        queue.put((tag, exc.code))
    finally:
        store.close()
