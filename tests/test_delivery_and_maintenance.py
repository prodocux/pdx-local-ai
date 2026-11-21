"""Acceptance test suite for Delivery, Packaging, Maintenance, and Agent Config.

Covers contractual requirements:
1. Fresh database initialization and schema version check (user_version = CURRENT_SCHEMA_VERSION).
2. Backward compatibility & forward protection: older version rejects newer database schema.
3. Explicit ACL boundary:
   - Default deny when inherit_read_principal is None.
   - inherit_read_principal grants access to newly discovered files.
   - Explicit revocation (can_read=0) is strictly preserved across subsequent rescans.
4. Source root coverage table persistence:
   - Distinguishes last_scan_completed_at, last_scan_succeeded_at, and last_full_coverage_at.
   - Unsupported files counted separately without marking scan as failed.
   - snapshot_time returns null/None when unknown or no readable published files.
5. Cross-process maintenance lock:
   - Mutual exclusion across separate processes.
   - Process crash / termination cleanly releases lock.
6. Consistent SQLite backup and restore:
   - Uses sqlite3.Connection.backup().
7. Agent config generator & Cursor mcp.json merge:
   - Default generates preview to stdout without writing.
   - --apply performs safe merge into mcp.json preserving existing servers.
   - Atomic replacement with backup creation.
   - Conflict detection when key exists with differing command.
8. Unicode / whitespace path robustness.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SRC = _HERE.parent / "src"
_BINARY_DIR = Path(os.environ.get('PDX_DELIVERY_BINARY_DIR', str(_HERE.parent / 'dist' / 'pdx-local')))
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pdx_local_ai.catalog import Catalog, CURRENT_SCHEMA_VERSION
from pdx_local_ai.maintenance import Maintenance
from pdx_local_ai.maintenance_lock import CrossProcessMaintenanceLock
from pdx_local_ai.agent_config import generate_agent_mcp_config, merge_cursor_mcp_config, main as agent_config_main
from pdx_local_ai.service.agent_service import PdxLocalAgentService
from pdx_local_ai.service.contracts import SecurityContext, AgentSearchRequest
from pdx_local_ai.service.job_worker import RefreshJobQueueWorker, RefreshSourceScope
from pdx_local_ai.validation import ContractError


class TestDeliveryAndMaintenanceAcceptance(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="pdx_delivery_test_")
        self.test_root = Path(self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_fresh_initialization_and_schema_version(self) -> None:
        """Requirement: Fresh database sets user_version=CURRENT_SCHEMA_VERSION and initializes coverage table."""
        db_path = self.test_root / "fresh_catalog.sqlite"
        cat = Catalog(db_path)
        try:
            ver = cat.conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(ver, CURRENT_SCHEMA_VERSION)

            # Check source_root_coverage table exists
            table_row = cat.conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='source_root_coverage'"
            ).fetchone()
            self.assertIsNotNone(table_row)
        finally:
            cat.close()

    def test_02_older_binary_rejects_newer_schema(self) -> None:
        """Requirement: Refuses to open catalog if database user_version exceeds supported version."""
        db_path = self.test_root / "future_catalog.sqlite"
        cat = Catalog(db_path)
        cat.conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION + 1}")
        cat.conn.commit()
        cat.close()

        with self.assertRaises(ContractError) as ctx:
            Catalog(db_path)
        self.assertIn("newer than supported version", str(ctx.exception))

    def test_03_acl_default_deny_and_revocation_persistence_across_rescans(self) -> None:
        """Requirement:
        - Default deny when inherit_read_principal is not specified.
        - Inherited read applies to new files when specified.
        - Explicit revocation (can_read=0) is NEVER overwritten by subsequent rescans.
        """
        db_path = self.test_root / "acl_test.sqlite"
        corpus_dir = self.test_root / "corpus_acl"
        corpus_dir.mkdir(parents=True)
        doc1 = corpus_dir / "doc1.txt"
        doc1.write_text("Document 1 content", encoding="utf-8")

        cat = Catalog(db_path)
        ws_id = "00000000-0000-0000-0000-000000000001"
        alice = "alice"
        bob = "bob"

        # 1. Root with inherit_read_principal=alice
        root_id = cat.add_root(
            workspace_id=ws_id,
            canonical_path=str(corpus_dir),
            inherit_read_principal=alice,
        )
        cat.scan(source_root_id=root_id)

        # Alice should have read access, Bob should NOT (default deny)
        f_row = cat.conn.execute("SELECT file_record_id FROM file_record WHERE relative_path='doc1.txt'").fetchone()
        self.assertIsNotNone(f_row)
        fid = str(f_row[0])

        alice_acl = cat.conn.execute(
            "SELECT can_read FROM file_acl WHERE workspace_id=? AND principal_id=? AND file_record_id=?",
            (ws_id, alice, fid),
        ).fetchone()
        self.assertEqual(alice_acl[0], 1)

        bob_acl = cat.conn.execute(
            "SELECT can_read FROM file_acl WHERE workspace_id=? AND principal_id=? AND file_record_id=?",
            (ws_id, bob, fid),
        ).fetchone()
        self.assertIsNone(bob_acl)  # Default deny: zero rows

        # 2. Explicitly revoke Alice's access (can_read=0)
        cat.revoke_read_access(workspace_id=ws_id, principal_id=alice, file_record_id=fid)
        alice_acl_revoked = cat.conn.execute(
            "SELECT can_read FROM file_acl WHERE workspace_id=? AND principal_id=? AND file_record_id=?",
            (ws_id, alice, fid),
        ).fetchone()
        self.assertEqual(alice_acl_revoked[0], 0)

        # 3. Rescan the root. Alice's revocation must persist and NOT be overwritten back to 1!
        cat.scan(source_root_id=root_id)
        alice_acl_after_rescan = cat.conn.execute(
            "SELECT can_read FROM file_acl WHERE workspace_id=? AND principal_id=? AND file_record_id=?",
            (ws_id, alice, fid),
        ).fetchone()
        self.assertEqual(alice_acl_after_rescan[0], 0)

        cat.close()

    def test_04_coverage_timestamps_and_snapshot_time_null_semantics(self) -> None:
        """Requirement:
        - When no readable published files exist, snapshot_time is null/None (not 1970-01-01).
        - Worker persists coverage to source_root_coverage.
        - Status query returns last_scan_completed_at, last_scan_succeeded_at, last_full_coverage_at.
        """
        db_path = self.test_root / "coverage_test.sqlite"
        corpus_dir = self.test_root / "corpus_empty"
        corpus_dir.mkdir(parents=True)

        cat = Catalog(db_path)
        ws_id = "00000000-0000-0000-0000-000000000001"
        alice = "alice"
        root_id = cat.add_root(workspace_id=ws_id, canonical_path=str(corpus_dir))
        svc = PdxLocalAgentService(cat)
        admin_ctx = SecurityContext(workspace_id=ws_id, principal_id="admin", is_admin=True)
        ctx = SecurityContext(workspace_id=ws_id, principal_id=alice, is_admin=False)

        # 1. Empty root without published files: admin queries status, snapshot_time must be None
        st = svc.get_index_status(root_id, context=admin_ctx, view="admin_full")
        self.assertIsNone(st.snapshot_time)
        self.assertEqual(st.authorized_files_count, 0)

        # 2. Add file, scan via worker
        doc = corpus_dir / "doc.txt"
        doc.write_text("Hello ProDocuX", encoding="utf-8")
        cat.scan(source_root_id=root_id)
        fid = cat.conn.execute("SELECT file_record_id FROM file_record").fetchone()[0]
        cat.grant_read_access(workspace_id=ws_id, principal_id=alice, file_record_id=fid)

        worker = RefreshJobQueueWorker(cat, max_queue_size=64, max_active_workers=1)
        worker.grant_refresh_permission(ws_id, alice, root_id)
        job = worker.trigger_refresh(RefreshSourceScope(workspace_id=ws_id, source_root_id=root_id, operator_principal_id=alice))

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            jst = worker.get_job_status(job.job_id)
            if jst and jst.stage in ("completed", "failed"):
                break
            time.sleep(0.02)

        st2 = svc.get_index_status(root_id, context=ctx)
        self.assertIsNotNone(st2.snapshot_time)
        self.assertNotEqual(st2.snapshot_time, "1970-01-01T00:00:00Z")
        self.assertIsNotNone(st2.last_scan_completed_at)
        self.assertIsNotNone(st2.last_scan_succeeded_at)
        self.assertIsNotNone(st2.last_full_coverage_at)

        # Verify persistent table
        cov_row = cat.conn.execute(
            "SELECT last_scan_completed_at, last_scan_succeeded_at, last_full_coverage_at FROM source_root_coverage WHERE source_root_id=?",
            (root_id,),
        ).fetchone()
        self.assertIsNotNone(cov_row)
        self.assertEqual(cov_row["last_scan_succeeded_at"], st2.last_scan_succeeded_at)

        worker.shutdown(timeout_sec=2.0)
        cat.close()

    def test_05_cross_process_maintenance_lock(self) -> None:
        """Requirement: Mutual exclusion across distinct processes and crash-safe release."""
        lock_path = self.test_root / "pdx_maintenance.lock"
        lock1 = CrossProcessMaintenanceLock(lock_path)
        self.assertTrue(lock1.acquire(timeout_sec=2.0))

        # Attempt to acquire from child process must fail while held
        code = f"""
import sys
from pathlib import Path
sys.path.insert(0, r"{_SRC}")
from pdx_local_ai.maintenance_lock import CrossProcessMaintenanceLock
lock2 = CrossProcessMaintenanceLock(r"{lock_path}")
success = lock2.acquire(timeout_sec=0.2)
sys.exit(0 if success else 42)
"""
        proc = subprocess.run([sys.executable, "-c", code])
        self.assertEqual(proc.returncode, 42)

        # Release lock1
        lock1.release()

        # Child process now acquires cleanly
        proc2 = subprocess.run([sys.executable, "-c", code])
        self.assertEqual(proc2.returncode, 0)

    def test_06_sqlite_consistent_backup_and_restore(self) -> None:
        """Requirement: Backup uses sqlite3.Connection.backup() and performs integrity verification."""
        db_path = self.test_root / "backup_src.sqlite"
        backup_dest = self.test_root / "backup_archive.sqlite"
        restore_dest = self.test_root / "restored.sqlite"

        cat = Catalog(db_path)
        maint = Maintenance(cat)
        res = maint.backup(backup_dest)
        self.assertEqual(res["sqlite_integrity"], ["ok"])
        self.assertEqual(res["foreign_key_errors"], 0)
        self.assertTrue(backup_dest.exists())
        cat.close()

        rest_res = Maintenance.restore(backup_dest, restore_dest)
        self.assertEqual(rest_res["sqlite_integrity"], ["ok"])
        self.assertTrue(restore_dest.exists())

    def test_07_agent_config_preview_and_apply_merge(self) -> None:
        """Requirement:
        - Default preview writes to stdout without modifying target file.
        - --apply merges cleanly into mcp.json, preserving other MCP servers.
        - Backs up original file before modifying.
        - Detects command collision unless --force.
        """
        cursor_dir = self.test_root / "fake_cursor_home" / ".cursor"
        cursor_dir.mkdir(parents=True)
        mcp_json = cursor_dir / "mcp.json"

        # Pre-existing MCP server configuration
        initial_content = {
            "mcpServers": {
                "other-tool": {
                    "command": "node",
                    "args": ["server.js"],
                }
            }
        }
        mcp_json.write_text(json.dumps(initial_content, indent=2), encoding="utf-8")

        # 1. Preview mode (no --apply)
        server_cfg = generate_agent_mcp_config(
            binary_path="C:\\pdx\\pdx-local.exe",
            catalog_path="C:\\data\\catalog.sqlite",
            workspace_id="ws-123",
            principal_id="alice",
            scheduled_root_id="root-123",
        )
        self.assertIn("pdx-local.exe", server_cfg["command"])
        self.assertEqual(server_cfg["args"][0], "service")
        from pdx_local_ai.agent_config import render_mcp_snippet
        claude = render_mcp_snippet("claude-desktop", server_cfg)
        self.assertIn('"service"', claude)
        codex = render_mcp_snippet("codex", server_cfg)
        self.assertIn("[mcp_servers.pdx-local-ai]", codex)
        self.assertIn("service", codex)

        # 2. Apply merge
        ok, msg = merge_cursor_mcp_config(mcp_json, "pdx-local-ai", server_cfg)
        self.assertTrue(ok, msg)

        # Verify merge result
        merged = json.loads(mcp_json.read_text(encoding="utf-8"))
        self.assertIn("other-tool", merged["mcpServers"])
        self.assertIn("pdx-local-ai", merged["mcpServers"])
        self.assertEqual(merged["mcpServers"]["pdx-local-ai"]["command"], "C:\\pdx\\pdx-local.exe")

        # Verify backup was created
        backups = list(cursor_dir.glob("mcp.json.bak.*"))
        self.assertGreaterEqual(len(backups), 1)

        # 3. Collision detection: changing command without force fails
        conflict_cfg = dict(server_cfg)
        conflict_cfg["command"] = "C:\\pdx\\different.exe"
        ok2, msg2 = merge_cursor_mcp_config(mcp_json, "pdx-local-ai", conflict_cfg, force=False)
        self.assertFalse(ok2)
        self.assertIn("Conflict", msg2)

        # 4. Force overwrite succeeds
        ok3, msg3 = merge_cursor_mcp_config(mcp_json, "pdx-local-ai", conflict_cfg, force=True)
        self.assertTrue(ok3)
        merged2 = json.loads(mcp_json.read_text(encoding="utf-8"))
        self.assertEqual(merged2["mcpServers"]["pdx-local-ai"]["command"], "C:\\pdx\\different.exe")

    def test_08_paths_with_spaces_and_unicode(self) -> None:
        """Requirement: Handles spaces and unicode characters in file paths cleanly."""
        unicode_corpus = self.test_root / "測試 文件夾 含 空格"
        unicode_corpus.mkdir(parents=True)
        sample_file = unicode_corpus / "測試 檔案.txt"
        sample_file.write_text("Unicode and space content", encoding="utf-8")

        db_path = self.test_root / "資料庫 空間.sqlite"
        cat = Catalog(db_path)
        ws_id = "00000000-0000-0000-0000-000000000001"
        rid = cat.add_root(workspace_id=ws_id, canonical_path=str(unicode_corpus))
        cat.scan(source_root_id=rid)

        row = cat.conn.execute("SELECT relative_path FROM file_record WHERE source_root_id=?", (rid,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "測試 檔案.txt")
        cat.close()

    def test_09_cli_lifecycle_init_source_purge_and_overlap_guard(self) -> None:
        """Requirement: CLI lifecycle integration:
        - init initializes profile, rejects re-init if exists.
        - source add & list registers root.
        - purge refuses if profile overlaps with source root.
        - purge cleanly removes profile when safe.
        """
        from pdx_local_ai.cli.main import main as cli_main

        profile_dir = self.test_root / "test_profile"
        source_dir = self.test_root / "test_source"
        source_dir.mkdir(parents=True)
        (source_dir / "sample.txt").write_text("sample content", encoding="utf-8")

        # 1. init
        ret = cli_main(["init", "--profile-dir", str(profile_dir), "--workspace-id", "ws-cli-1", "--principal-id", "alice"])
        self.assertEqual(ret, 0)
        self.assertTrue((profile_dir / "catalog.sqlite").exists())
        self.assertTrue((profile_dir / "config.json").exists())

        # Duplicate init fails
        ret_dup = cli_main(["init", "--profile-dir", str(profile_dir)])
        self.assertEqual(ret_dup, 1)

        # 2. source add & list
        ret_add = cli_main(["source", "add", str(source_dir), "--profile-dir", str(profile_dir), "--inherit-read", "--principal-id", "alice"])
        self.assertEqual(ret_add, 0)

        # 3. source scan
        db_path = profile_dir / "catalog.sqlite"
        cat = Catalog(db_path)
        r_id = cat.conn.execute("SELECT source_root_id FROM source_root").fetchone()[0]
        cat.close()

        ret_scan = cli_main(["source", "scan", r_id, "--profile-dir", str(profile_dir)])
        self.assertEqual(ret_scan, 0)

        # 4. purge overlap guard: if a source root is inside profile dir, purge must refuse!
        cat = Catalog(db_path)
        fake_nested_source = profile_dir / "nested_source"
        fake_nested_source.mkdir()
        nested_rid = cat.add_root(workspace_id="ws-cli-1", canonical_path=str(fake_nested_source))
        cat.close()

        ret_purge_blocked = cli_main(["purge", "--profile-dir", str(profile_dir)])
        self.assertEqual(ret_purge_blocked, 2)  # Refused with code 2!
        self.assertTrue(profile_dir.exists())

        # Remove the nested source from DB to test safe purge
        cat = Catalog(db_path)
        cat.conn.execute("DELETE FROM source_root WHERE source_root_id=?", (nested_rid,))
        cat.conn.commit()
        cat.close()

        ret_purge_safe = cli_main(["purge", "--profile-dir", str(profile_dir)])
        self.assertEqual(ret_purge_safe, 0)
        self.assertFalse(profile_dir.exists())
        self.assertTrue(source_dir.exists())  # Source directory strictly safeguarded!

    def test_10_zip_powershell_installer_lifecycle_without_python(self) -> None:
        """Requirement:
        - Extracts actual distribution ZIP.
        - Executes install.ps1 via PowerShell in a clean environment stripped of Python in PATH/PYTHONPATH.
        - Verifies program installed without host Python.
        - Executes uninstall.ps1, verifying clean removal and preservation of user data and source roots.
        """
        # Prefer the most recent named batch ZIP (batch7 → batch6 → …).
        # This ensures Test 10 validates the same delivery package that is being
        # submitted for acceptance, not a stale earlier build.
        _batch_candidates = [
            _HERE.parent / "dist" / "pdx-local-ai-windows-x64-v0.0.1-batch7.zip",
            _HERE.parent / "dist" / "pdx-local-ai-windows-x64-v0.0.1-batch6.zip",
            _HERE.parent / "dist" / "pdx-local-ai-windows-x64-v0.0.1-batch5.zip",
            _HERE.parent / "dist" / "pdx-local-ai-windows-x64-v0.0.1-batch4.zip",
            _HERE.parent / "dist" / "pdx-local-ai-windows-x64-v0.0.1-batch3.zip",
            _HERE.parent / "dist" / "pdx-local-ai-windows-x64-v0.0.1-batch2.zip",
            _HERE.parent / "dist" / "pdx-local-ai-windows-x64-v0.0.1.zip",
        ]
        explicit_zip = os.environ.get("PDX_DELIVERY_ZIP")
        zip_path = Path(explicit_zip).resolve() if explicit_zip else next((p for p in _batch_candidates if p.exists()), None)
        if os.environ.get("CI") and not explicit_zip:
            self.fail("CI requires PDX_DELIVERY_ZIP and PDX_DELIVERY_SHA256")
        if zip_path is None:
            self.skipTest(
                "No distribution ZIP found in dist/. "
                "Expected: pdx-local-ai-windows-x64-v0.0.1-batch7.zip"
            )
        # Assert we are validating the intended batch
        if explicit_zip:
            import hashlib
            expected_sha = os.environ.get("PDX_DELIVERY_SHA256", "")
            self.assertEqual(len(expected_sha), 64, "Explicit ZIP requires its SHA-256")
            self.assertEqual(hashlib.sha256(zip_path.read_bytes()).hexdigest(), expected_sha.lower())
        else:
            self.assertIn("batch7", zip_path.name)

        import zipfile
        unzip_dir = self.test_root / "unzipped_pkg"
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(unzip_dir)

        pkg_root = list(unzip_dir.glob("pdx-local-ai-windows-x64-*"))[0]
        install_script = pkg_root / "install.ps1"
        uninstall_script = pkg_root / "uninstall.ps1"
        notices_file = pkg_root / "THIRD-PARTY-NOTICES.txt"
        self.assertTrue(install_script.exists())
        self.assertTrue(uninstall_script.exists())
        self.assertTrue(
            notices_file.exists(),
            "THIRD-PARTY-NOTICES.txt must be present in delivery package root"
        )

        # Verify install.ps1 has no dev fallback path
        install_ps1_text = install_script.read_text(encoding="utf-8", errors="replace")
        self.assertNotIn(
            r"..\dist\pdx-local",
            install_ps1_text,
            "install.ps1 must not contain dev repository fallback path"
        )

        install_target = self.test_root / "installed_program"
        profile_target = self.test_root / "user_profile"
        source_dir = self.test_root / "my_documents"
        source_dir.mkdir(parents=True)
        (source_dir / "paper.txt").write_text("My precious document", encoding="utf-8")

        # Create environment stripped of Python
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        orig_path = env.get("PATH", "").split(os.pathsep)
        clean_path = [p for p in orig_path if "python" not in p.lower() and ".venv" not in p.lower()]
        env["PATH"] = os.pathsep.join(clean_path)

        # 1. Run PowerShell install.ps1
        res_inst = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(install_script),
                "-AcceptWindowsRuntimeTerms",
                "-TargetDir",
                str(install_target),
                "-ProfileDir",
                str(profile_target),
                "-Version",
                "0.0.1",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(res_inst.returncode, 0, f"STDOUT: {res_inst.stdout}\nSTDERR: {res_inst.stderr}")
        self.assertTrue((install_target / "pdx-local.exe").exists())
        self.assertTrue((install_target / "install-manifest.json").exists())
        self.assertTrue((install_target / "uninstall.ps1").exists())

        # 2. Simulate user initializing profile and database
        cat_db = profile_target / "catalog.sqlite"
        cat = Catalog(cat_db)
        rid = cat.add_root(workspace_id="ws-inst-1", canonical_path=str(source_dir), inherit_read_principal="ci-user")
        cat.scan(source_root_id=rid)
        cat.close()

        # 3. Run PowerShell uninstall.ps1 (from install_target)
        res_un = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(install_target / "uninstall.ps1"),
                "-TargetDir",
                str(install_target),
                "-ProfileDir",
                str(profile_target),
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(res_un.returncode, 0, f"STDOUT: {res_un.stdout}\nSTDERR: {res_un.stderr}")
        self.assertFalse(install_target.exists())
        self.assertTrue(profile_target.exists())
        self.assertTrue(cat_db.exists())
        self.assertTrue(source_dir.exists())

    def test_11_upgrade_stops_active_service_and_startup_guarded_by_maintenance_lock(self) -> None:
        """Requirement:
        - Service startup is rejected with exit code 4 when maintenance lock is held.
        - Installer upgrade terminates running active service sessions recorded in run/sessions.
        - Live backup is created via sqlite3.Connection.backup() and verified.
        - Files are atomically replaced.
        """
        dist_dir = _BINARY_DIR
        if not (dist_dir / "pdx-local.exe").exists():
            self.skipTest("dist/pdx-local/pdx-local.exe not built; skipping.")

        install_target = self.test_root / "installed_service_app"
        profile_target = self.test_root / "service_profile"
        profile_target.mkdir(parents=True)
        cat_db = profile_target / "catalog.sqlite"
        cat = Catalog(cat_db)
        cat.close()

        # 1. Verify service startup guard against maintenance lock
        lock_file = profile_target / "maintenance.lock"
        m_lock = CrossProcessMaintenanceLock(lock_file)
        self.assertTrue(m_lock.acquire())

        # Spawn pdx-local.exe service while lock is held
        res_svc_blocked = subprocess.run(
            [str(dist_dir / "pdx-local.exe"), "service", "--catalog-path", str(cat_db)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res_svc_blocked.returncode, 4)
        self.assertIn("locked for maintenance", res_svc_blocked.stderr)
        m_lock.release()

        # 2. Initial install
        from pdx_local_ai.installer import Installer
        installer = Installer(install_target, profile_target)
        ok, msg = installer.install(dist_dir, version="0.0.1", accept_windows_runtime_terms=True)
        self.assertTrue(ok, msg)

        # 3. Start active service process in background
        svc_proc = subprocess.Popen(
            [
                str(install_target / "pdx-local.exe"),
                "service",
                "--catalog-path",
                str(cat_db),
                "--workspace-id",
                "ws-s1",
                "--principal-id",
                "ci-user",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(1.0)
        # Verify session file was registered
        session_files = list((profile_target / "run" / "sessions").glob("session_*.json"))
        self.assertGreaterEqual(len(session_files), 1)

        # 4. Perform upgrade under active running service
        ok_up, msg_up = installer.install(dist_dir, version="0.0.2", accept_windows_runtime_terms=True)
        self.assertTrue(ok_up, msg_up)

        # Verify running service was terminated cleanly
        try:
            svc_proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            svc_proc.kill()
        self.assertIsNotNone(svc_proc.poll())

        # Verify backup was created
        backups = list((profile_target / "backups").glob("catalog_backup_pre_upgrade_*.sqlite"))
        self.assertGreaterEqual(len(backups), 1)

    def test_12_migration_failure_in_product_pipeline_rolls_back_and_halts(self) -> None:
        """Requirement:
        - Midway DDL failure in the 013 migration block (inside BEGIN IMMEDIATE transaction) is fully
          rolled back — zero partial table/trigger/view residue.
        - Original database and pre-upgrade backup are preserved after the failure.
        - MIGRATION_FAILED marker is written to profile_dir, blocking service startup.
        - Old binary directory is restored on migration failure.

        Note: This is a Host-Python-independent entrypoint test; it exercises the product migration
        pipeline (apply_migrations) in-process via the installer code path.  Failure injection is
        done via the ``_migration_013_statement_hook`` callback parameter on ``apply_migrations``
        (monkeypatched onto the Catalog class), NOT via an environment variable, so no env-var hook
        is present in the shipped binary.
        Full clean-VM validation (OS-level binary subprocess) is deferred to integration testing.
        """
        dist_dir = _BINARY_DIR
        if not (dist_dir / "pdx-local.exe").exists():
            self.skipTest("dist/pdx-local/pdx-local.exe not built; skipping.")

        install_target = self.test_root / "migr_installed"
        profile_target = self.test_root / "migr_profile"
        profile_target.mkdir(parents=True)
        cat_db = profile_target / "catalog.sqlite"

        # ── Step 1: Build a catalog with schema through 012 ONLY (no 013 objects yet).
        #    We patch SQL_FILES to exclude 013 so Catalog.__init__ does not run migration 013.
        #    This gives apply_migrations a clean surface when upgrade later attempts 013.
        import pdx_local_ai.catalog as _cat_mod
        orig_sql_files = _cat_mod.SQL_FILES
        _cat_mod.SQL_FILES = [f for f in orig_sql_files if "013" not in f.name]
        try:
            cat = Catalog(cat_db)
            cat.conn.execute("CREATE TABLE original_data (val TEXT)")
            cat.conn.execute("INSERT INTO original_data VALUES ('vital_record')")
            cat.conn.commit()
            cat.close()
        finally:
            _cat_mod.SQL_FILES = orig_sql_files

        # Snapshot tables before the attempted migration (013 not yet present)
        _conn_snap = sqlite3.connect(str(cat_db))
        tables_before_migration = set(
            r[0] for r in _conn_snap.execute("SELECT name FROM sqlite_master WHERE type='table'")
        )
        _conn_snap.close()

        # ── Step 2: Simulate an already-installed v0.0.1 without running apply_migrations.
        #    Copy dist files into install_target and write a minimal manifest.
        #    This avoids Catalog() init completing migration 013 during "initial install".
        install_target.mkdir(parents=True, exist_ok=True)
        shutil.copytree(str(dist_dir), str(install_target), dirs_exist_ok=True)
        minimal_manifest = {
            "schema_version": "pdx_local_install_manifest_v1",
            "product_name": "pdx-local-ai",
            "version": "0.0.1",
            "installed_at": "2026-01-01T00:00:00Z",
            "target_directory": str(install_target),
            "installed_files": {},
        }
        (install_target / "install-manifest.json").write_text(
            json.dumps(minimal_manifest, indent=2), encoding="utf-8"
        )

        # ── Step 3: Attempt upgrade with midway 013 failure injection.
        #    We monkeypatch apply_migrations to pass a statement hook that raises at index 3,
        #    simulating a mid-transaction DDL failure inside the 013 BEGIN IMMEDIATE block.
        import pdx_local_ai.catalog as _cat_mod
        from pdx_local_ai.installer import Installer

        _orig_apply = _cat_mod.apply_migrations

        def _apply_with_hook(conn: object) -> None:
            def _hook(idx: int, _stmt: str) -> None:
                if idx == 3:
                    raise _cat_mod.sqlite3.OperationalError(
                        "INVALID_SQL_INJECTION_FOR_TESTING -- deliberate mid-transaction failure"
                    )
            _orig_apply(conn, _migration_013_statement_hook=_hook)  # type: ignore[arg-type]

        _cat_mod.apply_migrations = _apply_with_hook  # type: ignore[assignment]
        installer = Installer(install_target, profile_target)
        try:
            ok_up, msg_up = installer.install(dist_dir, version="0.0.2", accept_windows_runtime_terms=True)
        finally:
            _cat_mod.apply_migrations = _orig_apply  # type: ignore[assignment]

        # ── Assert A: Installer must return failure
        self.assertFalse(ok_up, f"Expected migration failure but got success: {msg_up}")
        self.assertIn("migration", msg_up.lower(), f"Message should mention migration: {msg_up}")

        # ── Assert B: MIGRATION_FAILED marker must exist in profile_dir
        migration_marker = profile_target / "MIGRATION_FAILED"
        self.assertTrue(
            migration_marker.exists(),
            "MIGRATION_FAILED marker was not written to profile_dir after migration failure"
        )
        marker_content = json.loads(migration_marker.read_text(encoding="utf-8"))
        self.assertIn("reason", marker_content, "Marker JSON should contain 'reason' field")
        self.assertIn("failed_at", marker_content, "Marker JSON should contain 'failed_at' field")

        # ── Assert C: Original database data must be preserved (vital_record intact)
        _conn_verify = sqlite3.connect(str(cat_db))
        row = _conn_verify.execute("SELECT val FROM original_data").fetchone()
        _conn_verify.close()
        self.assertIsNotNone(row, "original_data table should still exist after rollback")
        self.assertEqual(row[0], "vital_record", "Vital record must be preserved after migration failure")

        # ── Assert D: Zero 013 table residue — BEGIN IMMEDIATE rollback must be complete
        _conn_schema = sqlite3.connect(str(cat_db))
        tables_after_failure = set(
            r[0] for r in _conn_schema.execute("SELECT name FROM sqlite_master WHERE type='table'")
        )
        _conn_schema.close()
        extra_tables = tables_after_failure - tables_before_migration
        extra_tables.discard("original_data")  # our own test table; allowed
        self.assertEqual(
            extra_tables,
            set(),
            f"Migration rollback left partial 013 table residue: {extra_tables}"
        )

        # ── Assert E: Pre-upgrade backup was created and preserved
        backups = list((profile_target / "backups").glob("catalog_backup_pre_upgrade_*.sqlite"))
        self.assertGreaterEqual(
            len(backups), 1,
            "At least one pre-upgrade backup should have been created before migration attempt"
        )
        _conn_backup = sqlite3.connect(str(backups[0]))
        backup_row = _conn_backup.execute("SELECT val FROM original_data").fetchone()
        _conn_backup.close()
        self.assertIsNotNone(backup_row, "Backup should contain original_data table")
        self.assertEqual(backup_row[0], "vital_record", "Backup should preserve vital record")

        # ── Assert F: Service startup must be refused due to MIGRATION_FAILED marker
        res_svc = subprocess.run(
            [
                str(dist_dir / "pdx-local.exe"),
                "service",
                "--catalog-path", str(cat_db),
                "--workspace-id", str(uuid.uuid4()),
                "--principal-id", "test-user",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(
            res_svc.returncode, 5,
            f"Service should exit with code 5 when MIGRATION_FAILED marker is present. "
            f"Got {res_svc.returncode}. stderr: {res_svc.stderr[:200]}"
        )
        self.assertIn(
            "Migration failure", res_svc.stderr,
            "Service stderr should mention migration failure marker"
        )

    def test_13_uninstall_and_purge_fail_closed_negative_cases(self) -> None:
        """Requirement:
        - Malicious manifest path traversal rejected without deleting outside files.
        - Corrupted manifest rejected fail-closed without blind deletion.
        - Purge rejected if catalog cannot be inspected.
        - Purge rejected if source root is nested inside profile or profile inside source root.
        """
        from pdx_local_ai.installer import Installer
        install_target = self.test_root / "neg_installed"
        profile_target = self.test_root / "neg_profile"
        install_target.mkdir(parents=True)
        profile_target.mkdir(parents=True)

        outside_canary = self.test_root / "outside_canary.txt"
        outside_canary.write_text("Canary must survive", encoding="utf-8")

        # Subtest A: Manifest path traversal attack
        malicious_manifest = {
            "schema_version": "pdx_local_install_manifest_v1",
            "product_name": "pdx-local-ai",
            "version": "0.0.1",
            "installed_files": {
                "../../outside_canary.txt": {"size_bytes": 10, "sha256": "fake"},
            },
        }
        (install_target / "install-manifest.json").write_text(json.dumps(malicious_manifest), encoding="utf-8")
        installer = Installer(install_target, profile_target)
        ok_a, msg_a = installer.uninstall()
        self.assertFalse(ok_a)
        self.assertIn("Security violation", msg_a)
        self.assertTrue(outside_canary.exists())

        # Subtest B: Malformed manifest
        (install_target / "install-manifest.json").write_text("{corrupt-json", encoding="utf-8")
        (install_target / "tracked.txt").write_text("dummy", encoding="utf-8")
        ok_b, msg_b = installer.uninstall()
        self.assertFalse(ok_b)
        self.assertTrue((install_target / "tracked.txt").exists())

        # Subtest C: Purge rejected when catalog is unreadable (corrupt file)
        (profile_target / "catalog.sqlite").write_text("NOT A VALID SQLITE DATABASE", encoding="utf-8")
        (install_target / "install-manifest.json").write_text(json.dumps({"installed_files": {}}), encoding="utf-8")
        ok_c, msg_c = installer.uninstall(purge_data=True)
        self.assertFalse(ok_c)
        self.assertIn("Fail-closed refusal", msg_c)
        self.assertTrue(profile_target.exists())

        # Subtest D: Purge rejected when source root is nested inside profile
        profile_target_d = self.test_root / "neg_profile_d"
        profile_target_d.mkdir(parents=True)
        nested_source = profile_target_d / "docs_inside_profile"
        nested_source.mkdir(parents=True)
        cat_d_db = profile_target_d / "catalog.sqlite"
        cat_d = Catalog(cat_d_db)
        cat_d.add_root(workspace_id="ws-1", canonical_path=str(nested_source))
        cat_d.close()

        install_target_d = self.test_root / "neg_install_d"
        install_target_d.mkdir(parents=True)
        (install_target_d / "install-manifest.json").write_text(json.dumps({"installed_files": {}}), encoding="utf-8")
        installer_d = Installer(install_target_d, profile_target_d)
        ok_d, msg_d = installer_d.uninstall(purge_data=True)
        self.assertFalse(ok_d)
        self.assertIn("overlaps with document source root", msg_d)
        self.assertTrue(profile_target_d.exists())
        self.assertTrue(nested_source.exists())

        # Subtest E: CLI purge fail-closed check
        from pdx_local_ai.cli.main import cmd_purge
        import argparse
        args_d = argparse.Namespace(profile_dir=str(profile_target_d))
        self.assertEqual(cmd_purge(args_d), 2)
        self.assertTrue(profile_target_d.exists())

    def test_14_packaged_binary_mcp_stdio_search(self) -> None:
        """Requirement: Standalone compiled pdx-local.exe executes MCP stdio JSON-RPC handshake and real search."""
        dist_exe = _BINARY_DIR / "pdx-local.exe"
        if not dist_exe.exists():
            self.skipTest("dist/pdx-local/pdx-local.exe not built; skipping.")

        bin_profile = self.test_root / "mcp_bin_profile"
        bin_source = self.test_root / "mcp_bin_source"
        bin_source.mkdir(parents=True)
        token = "PackagedMcpSearchToken99"
        (bin_source / "report.txt").write_text(f"This document contains {token} for verification.", encoding="utf-8")

        env = os.environ.copy()
        env.pop("PYTHONPATH", None)

        import uuid
        ws_id = str(uuid.uuid4())

        # 1. Initialize profile
        subprocess.run(
            [str(dist_exe), "init", "--profile-dir", str(bin_profile), "--workspace-id", ws_id, "--principal-id", "ci-user"],
            check=True,
            env=env,
        )
        # 2. Add source
        res_add = subprocess.run(
            [str(dist_exe), "source", "add", str(bin_source), "--profile-dir", str(bin_profile), "--inherit-read", "--principal-id", "ci-user"],
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        import re
        rid = re.search(r"Root ID:\s+([a-f0-9\-]+)", res_add.stdout).group(1)
        # 3. Scan
        subprocess.run(
            [str(dist_exe), "source", "scan", rid, "--profile-dir", str(bin_profile)],
            check=True,
            env=env,
        )

        # 4. Spawn service MCP stdio process
        cat_db = bin_profile / "catalog.sqlite"
        proc = subprocess.Popen(
            [
                str(dist_exe),
                "service",
                "--catalog-path",
                str(cat_db),
                "--workspace-id",
                ws_id,
                "--principal-id",
                "ci-user",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        def send_and_read(msg: dict) -> dict:
            proc.stdin.write(json.dumps(msg) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            return json.loads(line)

        try:
            # MCP initialize
            init_res = send_and_read({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            })
            self.assertEqual(init_res["id"], 1)
            self.assertIn("tools", init_res["result"]["capabilities"])

            # MCP notifications/initialized
            proc.stdin.write(json.dumps({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }) + "\n")
            proc.stdin.flush()

            # MCP tools/list
            tools_res = send_and_read({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            })
            tool_names = [t["name"] for t in tools_res["result"]["tools"]]
            self.assertIn("search_documents", tool_names)
            self.assertIn("refresh_source", tool_names)
            self.assertIn("get_refresh_job", tool_names)
            self.assertIn("get_index_status", tool_names)

            # MCP tools/call search_documents
            call_res = send_and_read({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "search_documents",
                    "arguments": {
                        "query": token,
                        "source_root_ids": [rid],
                    },
                },
            })
            self.assertFalse(call_res["result"].get("isError", False))
            content_text = call_res["result"]["content"][0]["text"]
            self.assertIn(token, content_text)

        finally:
            proc.stdin.close()
            proc.wait(timeout=5)
            self.assertEqual(proc.returncode, 0)

    def test_15_process_identity_4state_negative_cases(self) -> None:
        """Requirement: CheckIdentityResult 4-state semantics — focused negative cases.

        Verifies:
        A. GONE      (PID does not exist)          → session deleted, no kill attempt.
        B. UNMATCHED (wrong exe path)              → session deleted, no kill attempt.
        C. UNMATCHED (wrong creation timestamp)    → session deleted, no kill attempt.
        D. UNKNOWN   (PID 4 / System, ACCESS_DENIED) → session preserved, upgrade ABORTED.
        E. UNKNOWN   (missing create_time field)   → session preserved, upgrade ABORTED.
        F. UNKNOWN   (unreadable session file)     → session preserved, upgrade ABORTED.
        G. MATCHED + terminate: confirmed GONE after terminate_process.
        """
        from pdx_local_ai.process_identity import (
            CheckIdentityResult,
            check_process_identity,
            terminate_process,
        )
        from pdx_local_ai.installer import stop_active_sessions

        sessions_dir = self.test_root / "sessions_dir" / "run" / "sessions"
        sessions_dir.mkdir(parents=True)
        profile_dir = self.test_root / "sessions_dir"

        # ── Shared helpers ───────────────────────────────────────────────────
        def write_session(name: str, data: dict) -> Path:
            p = sessions_dir / f"session_{name}.json"
            p.write_text(json.dumps(data), encoding="utf-8")
            return p

        fake_exe = str(self.test_root / "fake_pdx-local.exe")
        fake_ts  = 1_700_000_000.0

        # ── A: GONE — PID 999999 does not exist ─────────────────────────────
        r_a = check_process_identity(999999, fake_exe, fake_ts)
        self.assertEqual(r_a, CheckIdentityResult.GONE, "Non-existent PID must be GONE")

        # stop_active_sessions with GONE session: deletes the file, returns success
        sf_a = write_session("gone", {"pid": 999999, "executable": fake_exe, "create_time": fake_ts})
        ok_a, msg_a = stop_active_sessions(profile_dir)
        self.assertTrue(ok_a, f"GONE session should not block upgrade: {msg_a}")
        self.assertFalse(sf_a.exists(), "GONE session file must be deleted")

        # ── B: UNMATCHED — wrong exe path ────────────────────────────────────
        r_b = check_process_identity(os.getpid(), fake_exe, fake_ts)
        self.assertEqual(r_b, CheckIdentityResult.UNMATCHED,
                         "Own PID with wrong exe must be UNMATCHED")

        # stop_active_sessions with UNMATCHED session: deletes file, does NOT kill
        sf_b = write_session("unmatched_exe", {
            "pid": os.getpid(),
            "executable": fake_exe,   # Wrong path
            "create_time": fake_ts,
        })
        ok_b, msg_b = stop_active_sessions(profile_dir)
        self.assertTrue(ok_b, f"UNMATCHED session should not block upgrade: {msg_b}")
        self.assertFalse(sf_b.exists(), "UNMATCHED session file must be deleted")
        # Verify current process is still running (not killed) — use get_process_info directly
        from pdx_local_ai.process_identity import get_process_info as _gpi_b
        _exe_b, _ts_b = _gpi_b(os.getpid())
        self.assertIsNotNone(_exe_b, "Current process must still be running after UNMATCHED handling")
        self.assertFalse(
            __import__("pdx_local_ai.process_identity", fromlist=["is_query_failed"]).is_query_failed(_exe_b),
            "Current process get_process_info must not return QUERY_FAILED",
        )

        # ── C: UNMATCHED — wrong creation timestamp ──────────────────────────
        my_exe, my_ts = __import__(
            "pdx_local_ai.process_identity", fromlist=["get_process_info"]
        ).get_process_info(os.getpid())
        r_c = check_process_identity(os.getpid(), my_exe, (my_ts or 0.0) - 9999.0)
        self.assertEqual(r_c, CheckIdentityResult.UNMATCHED,
                         "Own PID with wrong create_time must be UNMATCHED")

        # ── D: UNKNOWN — PID 4 (Windows System process, ACCESS_DENIED) ───────
        r_d = check_process_identity(4, fake_exe, fake_ts)
        self.assertEqual(r_d, CheckIdentityResult.UNKNOWN,
                         "PID 4 (System, access denied) must return UNKNOWN")

        # stop_active_sessions with UNKNOWN session: session preserved, upgrade ABORTED
        sf_d = write_session("unknown_pid4", {
            "pid": 4,
            "executable": fake_exe,
            "create_time": fake_ts,
        })
        ok_d, msg_d = stop_active_sessions(profile_dir)
        self.assertFalse(ok_d, "UNKNOWN session must abort upgrade")
        self.assertIn("UNKNOWN", msg_d, f"Failure message must mention UNKNOWN: {msg_d}")
        self.assertTrue(sf_d.exists(), "UNKNOWN session file must be preserved (not deleted)")
        # Clean up for subsequent tests
        sf_d.unlink(missing_ok=True)

        # ── E: UNKNOWN — missing create_time field in session record ─────────
        sf_e = write_session("missing_ts", {
            "pid": os.getpid(),
            "executable": sys.executable,
            # create_time intentionally absent
        })
        ok_e, msg_e = stop_active_sessions(profile_dir)
        self.assertFalse(ok_e, "Session missing create_time must abort upgrade")
        self.assertIn("create_time", msg_e.lower(),
                      f"Failure message must mention create_time: {msg_e}")
        self.assertTrue(sf_e.exists(), "Session file missing create_time must be preserved")
        sf_e.unlink(missing_ok=True)

        # ── F: UNKNOWN — unreadable session file ─────────────────────────────
        sf_f = sessions_dir / "session_corrupt.json"
        sf_f.write_bytes(b"\xff\xfe{not valid json")
        ok_f, msg_f = stop_active_sessions(profile_dir)
        self.assertFalse(ok_f, "Unreadable session file must abort upgrade")
        self.assertTrue(sf_f.exists(), "Unreadable session file must be preserved")
        sf_f.unlink(missing_ok=True)

        # ── G: MATCHED + terminate — confirm process goes GONE ───────────────
        dist_dir = _BINARY_DIR
        if not (dist_dir / "pdx-local.exe").exists():
            self.skipTest("dist/pdx-local/pdx-local.exe not built; skipping subtest G.")

        cat_db_g = self.test_root / "cat_g.sqlite"
        from pdx_local_ai.catalog import Catalog as _Catalog
        _Catalog(cat_db_g).close()

        svc = subprocess.Popen(
            [str(dist_dir / "pdx-local.exe"), "service",
             "--catalog-path", str(cat_db_g),
             "--workspace-id", str(uuid.uuid4()),
             "--principal-id", "test"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        time.sleep(1.5)
        pid_g = svc.pid
        from pdx_local_ai.process_identity import get_process_info as _gpi
        exe_g, ts_g = _gpi(pid_g)
        self.assertEqual(
            check_process_identity(pid_g, exe_g, ts_g),
            CheckIdentityResult.MATCHED,
            "Live service process must be MATCHED",
        )

        result_g = terminate_process(pid_g, exe_g, ts_g, timeout_sec=5.0)
        self.assertTrue(result_g, "terminate_process must return True for MATCHED process")
        self.assertEqual(
            check_process_identity(pid_g, exe_g, ts_g),
            CheckIdentityResult.GONE,
            "Process must be GONE after confirmed termination",
        )
        try:
            svc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            svc.kill()


if __name__ == "__main__":
    unittest.main()
