"""Durable, source-bound cache for read-only conversion and OCR operations."""
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import tempfile



MAX_RECORD = 5 * 1024 * 1024


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return sha256(encoded(value)).hexdigest()


@contextmanager
def file_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+b")
    if not path.stat().st_size:
        handle.write(b"0")
        handle.flush()
    handle.seek(0)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        raise ValueError("DERIVED_RECORD_BUSY") from exc
    try:
        yield
    finally:
        handle.seek(0)
        if os.name == "nt":
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


class RecordStore:
    def __init__(self, directory, *, backend):
        self.backend = backend
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.database = self.directory / "records.db"
        with self.connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS derived_record (
                record_key TEXT PRIMARY KEY, binding_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending','ready')),
                container_name TEXT, result_digest TEXT, execution_count INTEGER NOT NULL)""")

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.database)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def binding(self, fmt, raw, policy):
        return {"format": fmt, "source_sha256": sha256(raw).hexdigest(),
                "image_id": self.backend.image_id, "policy": policy,
                "profile": "pdx-local-derived-record-v1"}

    def project(self, fmt, raw, *, allow_conversion=False, allow_ocr=False, hook=None):
        if fmt not in {"rtf", "doc", "xls", "ppt", "png", "jpg", "jpeg", "tiff", "pdf"}:
            raise ValueError("BACKEND_FORMAT_UNSUPPORTED")
        if not 0 < len(raw) <= 4 * 1024 * 1024:
            raise ValueError("WAVE3_SOURCE_SIZE_LIMIT")
        if type(allow_conversion) is not bool or type(allow_ocr) is not bool:
            raise ValueError("INVALID_BACKEND_POLICY")
        if fmt in {"rtf", "doc", "xls", "ppt"} and allow_conversion is not True:
            raise ValueError("ISOLATED_CONVERTER_REQUIRED")
        if fmt in {"png", "jpg", "jpeg", "tiff", "pdf"} and allow_ocr is not True:
            raise ValueError("OPT_IN_OCR_BACKEND_REQUIRED")
        policy = {"allow_conversion": allow_conversion, "allow_ocr": allow_ocr}
        binding = self.binding(fmt, raw, policy)
        key = digest(binding)
        with file_lock(self.directory / (key + ".lock")):
            return self._project(key, binding, fmt, raw, policy, hook)

    def _project(self, key, binding, fmt, raw, policy, hook):
        with self.connect() as conn:
            conn.execute("INSERT OR IGNORE INTO derived_record VALUES (?,?,'pending',NULL,NULL,0)",
                         (key, encoded(binding).decode()))
            row = conn.execute("SELECT * FROM derived_record WHERE record_key=?", (key,)).fetchone()
        artifact = self.directory / (key + ".json")
        if row["binding_json"] != encoded(binding).decode():
            raise ValueError("DERIVED_BINDING_MISMATCH")
        if artifact.exists():
            if artifact.stat().st_size > MAX_RECORD:
                raise ValueError("DERIVED_RECORD_SIZE_LIMIT")
            if row["result_digest"] is None:
                raise ValueError("DERIVED_RECORD_UNANCHORED")
            staged = json.loads(artifact.read_text(encoding="utf-8"))
            result = staged["result"]
            actual = digest(result)
            if (staged["binding"] != binding or staged["result_digest"] != actual
                    or result["source_sha256"] != binding["source_sha256"]
                    or result["image_id"] != binding["image_id"]
                    or (row["result_digest"] is not None and row["result_digest"] != actual)):
                raise ValueError("DERIVED_RECORD_DIGEST_INVALID")
            with self.connect() as conn:
                conn.execute("UPDATE derived_record SET state='ready',result_digest=? WHERE record_key=?",
                             (actual, key))
            return result
        if row["state"] == "ready":
            raise ValueError("DERIVED_RECORD_MISSING")
        if row["container_name"]:
            self._recover_container(row["container_name"])
        def prepared(name):
            with self.connect() as conn:
                conn.execute("UPDATE derived_record SET container_name=? WHERE record_key=?", (name, key))
            if hook:
                hook("prepared")

        with self.connect() as conn:
            conn.execute("UPDATE derived_record SET execution_count=execution_count+1 WHERE record_key=?", (key,))
        result = self.backend.project(fmt, raw, lifecycle=prepared, **policy)
        record = {"binding": binding, "result": result, "result_digest": digest(result)}
        payload = encoded(record)
        if len(payload) > MAX_RECORD:
            raise ValueError("DERIVED_RECORD_SIZE_LIMIT")
        with self.connect() as conn:
            conn.execute("UPDATE derived_record SET result_digest=? WHERE record_key=?",
                         (record["result_digest"], key))
        fd, temporary = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, artifact)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        if hook:
            hook("staged")
        with self.connect() as conn:
            conn.execute("UPDATE derived_record SET state='ready',result_digest=? WHERE record_key=?",
                         (record["result_digest"], key))
        return result

    @staticmethod
    def _recover_container(name):
        import subprocess
        if not name.startswith("pdx-document-"):
            raise ValueError("DERIVED_CONTAINER_ID_INVALID")
        result = subprocess.run(["docker", "ps", "-a", "--filter", "name=^/" + name + "$",
                                 "--format={{.Names}}"], capture_output=True, timeout=10, check=True)
        if result.stdout.strip():
            ownership = subprocess.run(["docker", "inspect", "--format",
                "{{index .Config.Labels \"pdx.document.managed\"}}", name],
                capture_output=True, timeout=10, check=True)
            if ownership.stdout.strip() != b"true":
                raise ValueError("DERIVED_CONTAINER_OWNERSHIP_MISMATCH")
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=10, check=True)
