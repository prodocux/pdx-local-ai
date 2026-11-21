from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .catalog import Catalog
from .validation import ContractError


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class Maintenance:
    """Product-owned reconciliation, integrity, and SQLite backup operations."""

    def __init__(self, catalog: Catalog) -> None:
        self.catalog = catalog

    def reconcile(
        self,
        *,
        source_root_id: str,
        run_id: str | None = None,
        stale_retry_limit: int = 1,
        missing_retention_runs: int = 2,
    ) -> dict[str, Any]:
        if stale_retry_limit < 0 or missing_retention_runs < 1:
            raise ContractError("invalid reconciliation policy")
        root = self.catalog.conn.execute(
            "SELECT workspace_id FROM source_root WHERE source_root_id=? AND enabled=1",
            (source_root_id,),
        ).fetchone()
        if root is None:
            raise ContractError("enabled source root not found")
        now = _now()
        if run_id is None:
            run_id = str(uuid.uuid4())
            try:
                with self.catalog.conn:
                    self.catalog.conn.execute(
                        "INSERT INTO reconciliation_run VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (run_id, root["workspace_id"], source_root_id, "running", 0,
                         stale_retry_limit, missing_retention_runs, None, None,
                         now, now, None),
                    )
            except sqlite3.IntegrityError as exc:
                raise ContractError(
                    "source root already has a running reconciliation"
                ) from exc
        else:
            existing = self.catalog.conn.execute(
                "SELECT * FROM reconciliation_run WHERE reconciliation_run_id=?",
                (run_id,),
            ).fetchone()
            if existing is None or existing["source_root_id"] != source_root_id:
                raise ContractError("reconciliation run does not belong to source root")
            if existing["status"] != "running":
                raise ContractError("only a running reconciliation can resume")
            stale_retry_limit = int(existing["stale_retry_limit"])
            missing_retention_runs = int(existing["missing_retention_runs"])
            with self.catalog.conn:
                self.catalog.conn.execute(
                    "UPDATE reconciliation_run SET resumed_count=resumed_count+1, updated_at=? WHERE reconciliation_run_id=?",
                    (now, run_id),
                )

        passes: list[dict[str, int]] = []
        try:
            for retry in range(stale_retry_limit + 1):
                result = self.catalog.scan(source_root_id=source_root_id)
                passes.append(result)
                if result["stale"] == 0:
                    break
            retention = self._apply_missing_retention(
                source_root_id=source_root_id,
                run_id=run_id,
                missing_retention_runs=missing_retention_runs,
            )
            integrity = self.integrity_report()
            work_complete = passes[-1]["stale"] == 0 and passes[-1]["failed"] == 0
            status = "succeeded" if integrity["passed"] and work_complete else "failed"
            failure_code = None
            if not integrity["passed"]:
                failure_code = "INTEGRITY_FAILED"
            elif not work_complete:
                failure_code = "RETRY_EXHAUSTED"
            receipt = {
                "schema_version": "pdx_local_reconciliation_receipt_v1",
                "reconciliation_run_id": run_id,
                "workspace_id": str(root["workspace_id"]),
                "source_root_id": source_root_id,
                "status": status,
                "scan_passes": passes,
                "stale_retries_consumed": max(0, len(passes) - 1),
                "missing_retention": retention,
                "integrity": integrity,
                "completed_at": _now(),
            }
            with self.catalog.conn:
                self.catalog.conn.execute(
                    "UPDATE reconciliation_run SET status=?, result_json=?, failure_code=?, updated_at=?, completed_at=? WHERE reconciliation_run_id=?",
                    (status, _json(receipt), failure_code,
                     receipt["completed_at"], receipt["completed_at"], run_id),
                )
            return receipt
        except Exception:
            with self.catalog.conn:
                self.catalog.conn.execute(
                    "UPDATE reconciliation_run SET status='failed', failure_code='RECONCILIATION_FAILED', updated_at=?, completed_at=? WHERE reconciliation_run_id=?",
                    (_now(), _now(), run_id),
                )
            raise

    def _apply_missing_retention(
        self, *, source_root_id: str, run_id: str, missing_retention_runs: int
    ) -> dict[str, int]:
        rows = self.catalog.conn.execute(
            "SELECT file_record_id, catalog_status FROM file_record WHERE source_root_id=?",
            (source_root_id,),
        ).fetchall()
        deleted = 0
        missing = 0
        now = _now()
        with self.catalog.conn:
            for row in rows:
                file_id = str(row["file_record_id"])
                if row["catalog_status"] == "active":
                    self.catalog.conn.execute(
                        "INSERT INTO file_maintenance VALUES (?,0,NULL,?,NULL) "
                        "ON CONFLICT(file_record_id) DO UPDATE SET consecutive_missing_runs=0, first_missing_at=NULL, last_seen_run_id=excluded.last_seen_run_id, deleted_at=NULL",
                        (file_id, run_id),
                    )
                elif row["catalog_status"] == "missing":
                    missing += 1
                    self.catalog.conn.execute(
                        "INSERT INTO file_maintenance VALUES (?,1,?,?,NULL) "
                        "ON CONFLICT(file_record_id) DO UPDATE SET consecutive_missing_runs=consecutive_missing_runs+1, first_missing_at=coalesce(first_missing_at, excluded.first_missing_at), last_seen_run_id=excluded.last_seen_run_id",
                        (file_id, now, run_id),
                    )
                    count = int(self.catalog.conn.execute(
                        "SELECT consecutive_missing_runs FROM file_maintenance WHERE file_record_id=?",
                        (file_id,),
                    ).fetchone()[0])
                    if count >= missing_retention_runs:
                        self.catalog.conn.execute(
                            "UPDATE file_record SET catalog_status='deleted' WHERE file_record_id=?",
                            (file_id,),
                        )
                        self.catalog.conn.execute(
                            "UPDATE file_maintenance SET deleted_at=? WHERE file_record_id=?",
                            (now, file_id),
                        )
                        deleted += 1
        return {"currently_missing": missing, "transitioned_to_deleted": deleted}

    def integrity_report(self) -> dict[str, Any]:
        integrity_rows = [str(row[0]) for row in self.catalog.conn.execute("PRAGMA integrity_check")]
        foreign_key_errors = len(self.catalog.conn.execute("PRAGMA foreign_key_check").fetchall())
        orphan_fts = int(self.catalog.conn.execute(
            "SELECT count(*) FROM block_fts f LEFT JOIN block_instance b ON b.block_instance_id=f.block_instance_id WHERE b.block_instance_id IS NULL"
        ).fetchone()[0])
        missing_fts = int(self.catalog.conn.execute(
            "SELECT count(*) FROM block_instance b LEFT JOIN block_fts f ON f.block_instance_id=b.block_instance_id WHERE f.block_instance_id IS NULL"
        ).fetchone()[0])
        projection_mismatches = int(self.catalog.conn.execute(
            "SELECT count(*) FROM projection p LEFT JOIN (SELECT projection_id,count(*) n FROM block_instance GROUP BY projection_id) b ON b.projection_id=p.projection_id WHERE p.block_count != coalesce(b.n,0)"
        ).fetchone()[0])
        current_pointer_errors = int(self.catalog.conn.execute(
            "SELECT count(*) FROM file_record f LEFT JOIN source_version s ON s.source_version_id=f.current_source_version_id AND s.file_record_id=f.file_record_id WHERE f.current_source_version_id IS NOT NULL AND s.source_version_id IS NULL"
        ).fetchone()[0])
        passed = (
            integrity_rows == ["ok"]
            and foreign_key_errors == orphan_fts == missing_fts
            == projection_mismatches == current_pointer_errors == 0
        )
        return {
            "passed": passed,
            "sqlite_integrity": integrity_rows,
            "foreign_key_errors": foreign_key_errors,
            "orphan_fts_rows": orphan_fts,
            "missing_fts_rows": missing_fts,
            "projection_block_count_mismatches": projection_mismatches,
            "current_source_pointer_errors": current_pointer_errors,
        }

    def backup(self, destination: str | Path) -> dict[str, Any]:
        destination = Path(destination).resolve()
        if destination.exists():
            raise ContractError("backup destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        for row in self.catalog.conn.execute("SELECT canonical_path FROM source_root"):
            root = Path(str(row[0])).resolve()
            if destination == root or root in destination.parents:
                raise ContractError("backup destination must be outside indexed roots")
        temporary = destination.with_name(destination.name + ".partial")
        if temporary.exists():
            raise ContractError("backup temporary destination already exists")
        try:
            target = sqlite3.connect(temporary)
            try:
                self.catalog.conn.backup(target)
                target.commit()
                integrity = [str(row[0]) for row in target.execute("PRAGMA integrity_check")]
                foreign_keys = len(target.execute("PRAGMA foreign_key_check").fetchall())
            finally:
                target.close()
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        if integrity != ["ok"] or foreign_keys:
            temporary.unlink(missing_ok=True)
            raise ContractError("backup integrity verification failed")
        os.replace(temporary, destination)
        return {
            "path": str(destination),
            "size_bytes": destination.stat().st_size,
            "sha256": _sha256_file(destination),
            "sqlite_integrity": integrity,
            "foreign_key_errors": foreign_keys,
        }

    @staticmethod
    def restore(backup: str | Path, destination: str | Path) -> dict[str, Any]:
        backup = Path(backup).resolve(strict=True)
        destination = Path(destination).resolve()
        if destination.exists():
            raise ContractError("restore destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        source = sqlite3.connect(f"file:{quote(str(backup).replace(os.sep, '/'))}?mode=ro", uri=True)
        temporary = destination.with_name(destination.name + ".partial")
        if temporary.exists():
            source.close()
            raise ContractError("restore temporary destination already exists")
        try:
            target = sqlite3.connect(temporary)
            try:
                if [str(row[0]) for row in source.execute("PRAGMA integrity_check")] != ["ok"]:
                    raise ContractError("source backup integrity verification failed")
                source.backup(target)
                target.commit()
                integrity = [str(row[0]) for row in target.execute("PRAGMA integrity_check")]
                foreign_keys = len(target.execute("PRAGMA foreign_key_check").fetchall())
            finally:
                source.close()
                target.close()
        except Exception:
            source.close()
            temporary.unlink(missing_ok=True)
            raise
        if integrity != ["ok"] or foreign_keys:
            temporary.unlink(missing_ok=True)
            raise ContractError("restored database integrity verification failed")
        os.replace(temporary, destination)
        return {
            "path": str(destination),
            "size_bytes": destination.stat().st_size,
            "sha256": _sha256_file(destination),
            "sqlite_integrity": integrity,
            "foreign_key_errors": foreign_keys,
        }
