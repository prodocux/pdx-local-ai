"""Offline shadow migration with preserved file IDs and immutable legacy citations."""
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

from .expanded_formats import MEDIA
from .source_replay import resolve
from pdx_local_ai.catalog import Catalog
from .derived_records import digest


@contextmanager
def connect(path):
    conn = sqlite3.connect(path)
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



class SnapshotCatalog(Catalog):
    """Open a retained generation for read-only source replay without running migrations."""
    def __init__(self, path, *, extractor):
        self.database = str(path)
        self.conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA query_only=ON")
        self.extractor = extractor
        self._kernel_adapter = None


def product_tables(conn):
    rows = conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table' "
                        "AND name NOT LIKE 'sqlite_%' AND name NOT IN ('pdx_write_fence','pdx_legacy_citation')").fetchall()
    virtual = [row[0] for row in rows if (row[1] or "").startswith("CREATE VIRTUAL")]
    return [name for name, sql in rows if name not in virtual
            and not any(name.startswith(prefix + "_") for prefix in virtual)]


def table_rows(conn, table):
    records = [{key: ({"bytes_hex": value.hex()} if isinstance(value, bytes) else value)
                for key, value in dict(row).items()}
               for row in conn.execute('SELECT * FROM "' + table + '"')]
    return sorted(records, key=lambda row: json.dumps(row, sort_keys=True))


def logical(conn):
    return digest({table: table_rows(conn, table) for table in product_tables(conn)})


def fence(conn, sealed):
    conn.execute("CREATE TABLE IF NOT EXISTS pdx_write_fence (id INTEGER PRIMARY KEY, sealed INTEGER NOT NULL)")
    conn.execute("INSERT OR IGNORE INTO pdx_write_fence VALUES (1,0)")
    tables = ("source_root", "file_record", "index_attempt", "source_version",
              "projection", "block_instance", "file_acl", "citation", "retrieval_receipt")
    for table in tables:
        # FTS virtual tables do not support triggers; their base Catalog tables are fenced.
        definition = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (table,)).fetchone()[0]
        if definition.startswith("CREATE VIRTUAL"):
            continue
        for operation in ("INSERT", "UPDATE", "DELETE"):
            trigger = "pdx_fence_" + table + "_" + operation
            conn.execute(f'CREATE TRIGGER IF NOT EXISTS "{trigger}" BEFORE {operation} ON "{table}" '
                         "WHEN (SELECT sealed FROM pdx_write_fence WHERE id=1)=1 "
                         "BEGIN SELECT RAISE(ABORT,'CATALOG_GENERATION_SEALED'); END")
    conn.execute("UPDATE pdx_write_fence SET sealed=? WHERE id=1", (int(sealed),))


def inventory(catalog, root_id):
    row = catalog.conn.execute("SELECT canonical_path FROM source_root WHERE source_root_id=?", (root_id,)).fetchone()
    root = Path(row[0])
    result = {}
    for path in catalog._enumerate(root, extensions=MEDIA):
        relative = str(path.relative_to(root)).replace("/", "\\")
        _, _, fingerprint = catalog._read_stable(root, path)
        result[relative] = fingerprint
    return result


def prepare(old, destination, *, root_id, extractor, hook=None):
    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError("SHADOW_REQUIRES_NEW_PATH")
    old.conn.execute("BEGIN IMMEDIATE")
    shadow = None
    try:
        root = old.conn.execute("SELECT * FROM source_root WHERE source_root_id=? AND enabled=1",
                                (root_id,)).fetchone()
        if root is None:
            raise ValueError("MIGRATION_ROOT_UNAVAILABLE")
        expected = inventory(old, root_id)
        active = old.conn.execute("""SELECT f.relative_path,v.source_sha256 FROM file_record f
            JOIN source_version v ON f.current_source_version_id=v.source_version_id
            WHERE f.source_root_id=? AND f.catalog_status='active'""", (root_id,)).fetchall()
        if any(expected.get(row[0]) != row[1] for row in active):
            raise ValueError("MIGRATION_SOURCE_CHANGED")
        before = logical(old.conn)
        shadow = Catalog(destination, format_adapter=extractor)
        supported = {"source_root", "file_record", "index_attempt", "source_version",
                     "projection", "block_instance", "file_acl", "citation", "retrieval_receipt",
                     "source_root_coverage", "source_projection_owner"}
        if old.conn.execute("SELECT count(*) FROM source_root").fetchone()[0] != 1:
            raise ValueError("MIGRATION_REQUIRES_SINGLE_ROOT")
        candidate_tables = set(product_tables(shadow.conn))
        for table in product_tables(old.conn):
            if table not in supported and (table not in candidate_tables
                    or table_rows(old.conn, table) != table_rows(shadow.conn, table)):
                raise ValueError("MIGRATION_UNSUPPORTED_PRODUCT_STATE")
        with shadow.conn:
            shadow.conn.execute("INSERT INTO source_root VALUES (?,?,?,?,?,?)", tuple(root))
            for row in old.conn.execute("SELECT * FROM file_record WHERE source_root_id=?", (root_id,)):
                data = dict(row)
                data["current_source_version_id"] = None
                names = list(data)
                shadow.conn.execute("INSERT INTO file_record (" + ",".join(names) + ") VALUES (" +
                                    ",".join("?" for _ in names) + ")", tuple(data.values()))
            for row in old.conn.execute("""SELECT a.* FROM file_acl a JOIN file_record f
                ON a.file_record_id=f.file_record_id WHERE f.source_root_id=?""", (root_id,)):
                shadow.conn.execute("INSERT INTO file_acl VALUES (?,?,?,?)", tuple(row))
        counts = shadow.scan(source_root_id=root_id, raise_on_error=True)
        if hook:
            hook("built", shadow)
        if inventory(old, root_id) != expected or inventory(shadow, root_id) != expected:
            raise ValueError("MIGRATION_SOURCE_CHANGED")
        observed = dict(shadow.conn.execute("""SELECT f.relative_path,v.source_sha256 FROM file_record f
            JOIN source_version v ON f.current_source_version_id=v.source_version_id
            WHERE f.source_root_id=? AND f.catalog_status='active'""", (root_id,)))
        if observed != expected:
            raise ValueError("MIGRATION_INVENTORY_MISMATCH")
        # Scan may inherit grants, but explicit existing deny/read decisions win.
        with shadow.conn:
            for row in old.conn.execute("SELECT * FROM file_acl"):
                if shadow.conn.execute("SELECT 1 FROM file_record WHERE file_record_id=?", (row[2],)).fetchone():
                    shadow.conn.execute("INSERT OR REPLACE INTO file_acl VALUES (?,?,?,?)", tuple(row))
            shadow.conn.execute("""CREATE TABLE pdx_legacy_citation (
                citation_id TEXT PRIMARY KEY, generation TEXT NOT NULL, file_record_id TEXT NOT NULL)""")
            for row in old.conn.execute("SELECT citation_id,file_record_id FROM citation WHERE source_root_id=?", (root_id,)):
                shadow.conn.execute("INSERT INTO pdx_legacy_citation VALUES (?,?,?)",
                                    (row[0], str(Path(old.database).resolve()), row[1]))
        assert shadow.conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert not shadow.conn.execute("PRAGMA foreign_key_check").fetchall()
        record = {"old": str(Path(old.database).resolve()), "new": str(destination), "root_id": root_id,
                  "logical_before": before, "inventory": expected,
                  "new_logical": logical(shadow.conn), "counts": counts}
        return record
    finally:
        if shadow is not None:
            shadow.close()
        old.conn.rollback()


class Gateway:
    """All managed host requests take the control transaction before a Catalog connection."""
    def __init__(self, database, initial):
        self.database = Path(database)
        with connect(self.database) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS active (id INTEGER PRIMARY KEY, path TEXT, revision INTEGER)")
            conn.execute("INSERT OR IGNORE INTO active VALUES (1,?,0)", (str(Path(initial).resolve()),))
            conn.execute("CREATE TABLE IF NOT EXISTS intent (id INTEGER PRIMARY KEY, data TEXT NOT NULL)")

    @contextmanager
    def session(self, extractor):
        with connect(self.database) as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM intent").fetchone():
                raise ValueError("CATALOG_RECOVERY_REQUIRED")
            path = conn.execute("SELECT path FROM active WHERE id=1").fetchone()[0]
            catalog = Catalog(path, format_adapter=extractor)
            try:
                yield catalog
            finally:
                catalog.close()

    def switch(self, record, *, hook=None):
        with connect(self.database) as conn:
            conn.execute("BEGIN IMMEDIATE")
            active = conn.execute("SELECT path FROM active WHERE id=1").fetchone()[0]
            if active != record["old"] or conn.execute("SELECT 1 FROM intent").fetchone():
                raise ValueError("CATALOG_CAS_CONFLICT")
            with connect(record["old"]) as old:
                old.execute("BEGIN IMMEDIATE")
                if logical(old) != record["logical_before"]:
                    raise ValueError("MIGRATION_STATE_CHANGED")
            with connect(record["new"]) as candidate:
                if logical(candidate) != record["new_logical"]:
                    raise ValueError("SHADOW_STATE_CHANGED")
            conn.execute("INSERT INTO intent VALUES (1,?)", (json.dumps(record),))
        self.recover(hook=hook)

    def recover(self, *, hook=None):
        with connect(self.database) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT data FROM intent WHERE id=1").fetchone()
            if row is None:
                return
            record = json.loads(row[0])
            with connect(record["old"]) as old:
                old.execute("BEGIN IMMEDIATE")
                if logical(old) != record["logical_before"]:
                    raise ValueError("MIGRATION_STATE_CHANGED")
                probe = SnapshotCatalog(record["old"], extractor=lambda *args: None)
                try:
                    if inventory(probe, record["root_id"]) != record["inventory"]:
                        raise ValueError("MIGRATION_SOURCE_CHANGED")
                finally:
                    probe.close()
                fence(old, True)
            if hook:
                hook("old_sealed")
            with connect(record["new"]) as new:
                new.execute("BEGIN IMMEDIATE")
                if logical(new) != record["new_logical"]:
                    raise ValueError("SHADOW_STATE_CHANGED")
                fence(new, False)
            conn.execute("UPDATE active SET path=?,revision=revision+1 WHERE id=1", (record["new"],))
            conn.execute("DELETE FROM intent")

    def abort_pending(self):
        """Trusted operator cancellation before a pending pointer becomes active."""
        with connect(self.database) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT data FROM intent WHERE id=1").fetchone()
            if row is None:
                return
            record = json.loads(row[0])
            active = conn.execute("SELECT path FROM active WHERE id=1").fetchone()[0]
            if active != record["old"]:
                raise ValueError("CATALOG_CAS_CONFLICT")
            with connect(record["new"]) as new:
                fence(new, True)
            with connect(record["old"]) as old:
                fence(old, False)
            conn.execute("DELETE FROM intent")

    def rollback(self, record):
        with connect(self.database) as conn:
            current = conn.execute("SELECT path FROM active WHERE id=1").fetchone()[0]
        if current != record["new"]:
            raise ValueError("CATALOG_CAS_CONFLICT")
        with connect(record["new"]) as new:
            if logical(new) != record["new_logical"]:
                raise ValueError("ROLLBACK_WOULD_LOSE_WRITES")
        reverse = {**record, "old": record["new"], "new": record["old"],
                   "logical_before": record["new_logical"], "new_logical": record["logical_before"]}
        self.switch(reverse)

    def resolve_legacy(self, citation_id, *, workspace_id, principal_id, root_id, extractor, old_extractor):
        with self.session(extractor) as active:
            active.conn.execute("BEGIN IMMEDIATE")
            route = active.conn.execute("SELECT * FROM pdx_legacy_citation WHERE citation_id=?", (citation_id,)).fetchone()
            if route is None:
                raise ValueError("LEGACY_CITATION_UNAVAILABLE")
            authorized = active.conn.execute("""SELECT v.source_sha256 FROM file_acl a JOIN file_record f
                ON a.file_record_id=f.file_record_id AND a.workspace_id=f.workspace_id
                JOIN source_version v ON v.source_version_id=f.current_source_version_id
                JOIN source_root r ON r.source_root_id=f.source_root_id AND r.enabled=1
                WHERE a.workspace_id=? AND a.principal_id=?
                AND a.file_record_id=? AND a.can_read=1 AND f.catalog_status='active'
                AND f.source_root_id=?""", (workspace_id, principal_id, route["file_record_id"], root_id)).fetchone()
            if authorized is None:
                raise ValueError("LEGACY_CITATION_UNAVAILABLE")
            old = SnapshotCatalog(route["generation"], extractor=old_extractor)
            try:
                original = old.conn.execute("SELECT source_sha256 FROM citation WHERE citation_id=?",
                                            (citation_id,)).fetchone()
                if original is None or original[0] != authorized[0]:
                    raise ValueError("LEGACY_CITATION_STALE_SOURCE")
                return resolve(old, citation_id, workspace_id=workspace_id, principal_id=principal_id,
                               root_id=root_id, extractor=old_extractor, acl_database=active.database)
            finally:
                old.close()
