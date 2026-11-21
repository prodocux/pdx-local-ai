"""External sends keep one operation. Local seals stay on ArtifactRuntime."""

from __future__ import annotations

import hashlib
import sqlite3

import pytest

from pdx_local_ai.external_action import ExternalActionError, ExternalActionHost
from pdx_local_ai.provenance import create_index_provenance
from pdx_local_ai.tasks.dispatcher import EngineAdapter

CLOCK = 1_700_000_000.0
PAYLOAD = {"action": "upload", "body": {"name": "notes"}}


def _host(tmp_path, submit, *, clock=lambda: CLOCK):
    return ExternalActionHost(tmp_path / "external.sqlite3", submit, clock=clock)


def _operations(host) -> int:
    with sqlite3.connect(host._store.path) as connection:
        return connection.execute("SELECT count(*) FROM external_operations").fetchone()[0]


def test_same_subject_and_payload_keep_one_operation(tmp_path) -> None:
    seen: list[str] = []

    def submit(payload, key):
        seen.append(key)

    host = _host(tmp_path, submit)
    first = host.perform("subject-upload-01", PAYLOAD)
    second = host.perform("subject-upload-01", PAYLOAD)
    assert first["operation_id"] == second["operation_id"]
    assert first["provider_key_digest"] == second["provider_key_digest"]
    assert first["disposition"] == "needs_review"
    assert first["submission_evidence"] == "possibly_submitted"
    assert seen == [seen[0]]
    assert _operations(host) == 1
    reopened = _host(tmp_path, submit)
    third = reopened.perform("subject-upload-01", PAYLOAD)
    assert third["operation_id"] == first["operation_id"]
    assert third["provider_key_digest"] == first["provider_key_digest"]
    assert seen == [seen[0]]
    assert _operations(reopened) == 1


def test_timeout_after_intent_does_not_create_a_second_operation(tmp_path) -> None:
    seen: list[str] = []

    def submit(payload, key):
        seen.append(key)
        raise TimeoutError("provider timed out")

    host = _host(tmp_path, submit)
    first = host.perform("subject-upload-02", PAYLOAD)
    second = host.perform("subject-upload-02", PAYLOAD)
    assert first["operation_id"] == second["operation_id"]
    assert first["provider_key_digest"] == second["provider_key_digest"]
    assert first["disposition"] == "needs_review"
    assert first["provider_outcome"] == "unknown"
    assert seen == [seen[0]]
    assert _operations(host) == 1


def test_failure_before_intent_retries_the_same_operation(tmp_path) -> None:
    seen: list[str] = []

    def submit(payload, key):
        seen.append(key)

    host = _host(tmp_path, submit)
    original = host.service.submit
    calls = {"n": 0}

    def fail_once(operation_id, principal):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("stopped before intent")
        return original(operation_id, principal)

    host.service.submit = fail_once
    with pytest.raises(RuntimeError, match="stopped before intent"):
        host.perform("subject-upload-03", PAYLOAD)
    assert _operations(host) == 1
    assert seen == []
    result = host.perform("subject-upload-03", PAYLOAD)
    assert result["disposition"] == "needs_review"
    assert seen and _operations(host) == 1


def test_changed_payload_conflicts_and_keeps_the_original_operation(tmp_path) -> None:
    host = _host(tmp_path, lambda payload, key: None)
    first = host.perform("subject-upload-04", PAYLOAD)
    with pytest.raises(ExternalActionError) as caught:
        host.perform("subject-upload-04", {"action": "upload", "body": {"name": "other"}})
    assert caught.value.code == "IDEMPOTENCY_CONFLICT"
    assert _operations(host) == 1
    assert host.perform("subject-upload-04", PAYLOAD)["operation_id"] == first["operation_id"]


def test_local_seal_is_unchanged_when_an_external_operation_exists(tmp_path) -> None:
    data = b"local-candidate"
    digest = hashlib.sha256(data).hexdigest()
    before = EngineAdapter(tmp_path / "seal-before").seal(
        task_id="task-local-seal", attempt_id="attempt-before",
        name="notes.txt", data=data, sha256=digest,
    )
    host = _host(tmp_path, lambda payload, key: None)
    sent = host.perform("subject-upload-05", PAYLOAD)
    after = EngineAdapter(tmp_path / "seal-after").seal(
        task_id="task-local-seal", attempt_id="attempt-after",
        name="notes.txt", data=data, sha256=digest,
    )
    assert before["engine_status"] == after["engine_status"] == "completed"
    assert before["origin"] == after["origin"] == "engine"
    assert before["engine_review"] is False and after["engine_review"] is False
    assert before["manifest_files"][0]["sha256"] == after["manifest_files"][0]["sha256"] == digest
    assert sent["disposition"] == "needs_review"


def test_a_later_subject_is_accepted_after_the_first_window(tmp_path) -> None:
    state = {"now": CLOCK}
    seen: list[str] = []

    def submit(payload, key):
        seen.append(key)

    host = _host(tmp_path, submit, clock=lambda: state["now"])
    first = host.perform("subject-early-01", PAYLOAD)
    state["now"] += 60
    second = host.perform("subject-later-02", {"action": "upload", "body": {"name": "later"}})
    state["now"] += 7200
    third = host.perform("subject-hours-03", {"action": "upload", "body": {"name": "hours"}})
    replay = host.perform("subject-early-01", PAYLOAD)
    host.close()
    assert len({first["operation_id"], second["operation_id"], third["operation_id"]}) == 3
    assert replay["operation_id"] == first["operation_id"]
    assert replay["provider_key_digest"] == first["provider_key_digest"]
    assert second["disposition"] == third["disposition"] == "needs_review"
    assert len(seen) == 3
    assert _operations(host) == 3


def test_provenance_records_kernel_engine_contract_profile_and_revision() -> None:
    bundle = create_index_provenance(
        attempt_id="attempt-1", source_version_id="source-1", projection_id="projection-1",
        source_sha256="a" * 64, projection_sha256="b" * 64, generated_at="2026-11-19T00:00:00Z",
        parser_contract="prodocux_archive_member_v1@1",
        archive_profile="zip-store-deflate", catalog_revision="catalog-1",
    )
    attributes = bundle["agents"][0]["attributes"]
    assert attributes["kernel_version"]
    assert attributes["engine_version"]
    assert attributes["parser_contract"] == "prodocux_archive_member_v1@1"
    assert attributes["archive_profile"] == "zip-store-deflate"
    assert attributes["catalog_revision"] == "catalog-1"
