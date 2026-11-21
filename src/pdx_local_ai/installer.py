"""ProDocuX Local AI Windows Delivery and Installer Shell Engine.

Key Contracts:
1. First install: Copies binary distribution to target directory, writes verified install-manifest.json.
2. Upgrade / Reinstall:
   - Acquires CrossProcessMaintenanceLock spanning the entire upgrade sequence.
   - Stops active running sessions with PID + exact executable + creation-time identity verification.
     If any session cannot be verified and stopped, upgrade is aborted (sessions are NEVER deleted
     before confirmation of stop success).
   - If user catalog exists, executes consistent SQLite backup via sqlite3.Connection.backup().
   - Stages files, then atomically replaces target with staged content.
   - Keeps old directory until migration verification completes (NOT deleted immediately on swap).
   - Runs DB migrations under the maintenance lock using apply_migrations() from the product pipeline.
   - On migration failure: writes migration_failed marker, old directory is restored, no data deleted.
   - Safely releases maintenance lock.
3. Service startup (stdio_transport):
   - Checks maintenance lock (fail with exit 4 if held).
   - Acquires maintenance lock before writing session file to prevent TOCTOU race.
   - Reads and embeds process creation time into session record for subsequent identity verification.
   - Checks migration_failed marker (fail with exit 5 if present).
4. Uninstall & Purge (Fail-Closed):
   - Preserves user profile data and document sources by default.
   - Manifest path traversal validation (reject .. or escaping paths).
   - Only removes files tracked in install-manifest.json; preserves untracked files.
   - Fail-closed: If inspecting catalog fails during purge, strictly refuse to delete.
   - Checks ALL 3 overlap directions (profile==source, source in profile.parents, profile in source.parents).
   - Checks recursive reparse points and symlinks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import sys
import time
from pathlib import Path
from typing import Any

from pdx_local_ai.maintenance_lock import CrossProcessMaintenanceLock
from pdx_local_ai.process_identity import (
    CheckIdentityResult,
    check_process_identity,
    get_process_info,
    is_query_failed,
    terminate_process,
    verify_process_identity,
)

# Marker file name in profile_dir indicating a failed migration
MIGRATION_FAILED_MARKER = "MIGRATION_FAILED"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        info = os.lstat(path)
        is_reparse = bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return is_reparse or stat.S_ISLNK(info.st_mode)
    except Exception:
        return False


def stop_active_sessions(profile_dir: Path, timeout_sec: float = 5.0) -> tuple[bool, str]:
    """Attempt to stop all active sessions recorded in profile_dir/run/sessions.

    Returns (True, "") if all sessions were stopped (or none existed).
    Returns (False, reason) if any session cannot be safely stopped.

    4-state identity semantics (CheckIdentityResult):
    - MATCHED   → attempt graceful termination.
    - UNMATCHED → PID recycled by a different process; delete stale session, do NOT kill.
    - GONE      → process already exited; delete stale session file.
    - UNKNOWN   → identity cannot be determined; ABORT upgrade, leave session file intact.

    Field-completeness rule:
    A session record missing pid / executable / create_time has UNKNOWN identity
    → ABORT upgrade.  Unreadable session files are also UNKNOWN.
    """
    sessions_dir = profile_dir / "run" / "sessions"
    if not sessions_dir.exists():
        return True, ""

    failures: list[str] = []
    for s_file in list(sessions_dir.glob("session_*.json")):
        # ── Parse session record ────────────────────────────────────────────
        try:
            data = json.loads(s_file.read_text(encoding="utf-8"))
        except Exception as exc:
            # Unreadable → UNKNOWN → ABORT (do not delete)
            failures.append(
                f"Cannot read session file {s_file.name}: {exc} — identity unknown, aborting upgrade"
            )
            continue

        pid       = data.get("pid")
        exe       = data.get("executable")
        create_ts = data.get("create_time")

        # All three fields are required for identity check; absence is UNKNOWN
        if not isinstance(pid, int):
            failures.append(
                f"Session {s_file.name}: missing/invalid 'pid' — identity unknown, aborting upgrade"
            )
            continue
        if not exe:
            failures.append(
                f"Session {s_file.name}: missing 'executable' — identity unknown, aborting upgrade"
            )
            continue
        if create_ts is None:
            failures.append(
                f"Session {s_file.name}: missing 'create_time' — identity unknown, aborting upgrade"
            )
            continue

        # ── 4-state identity check ──────────────────────────────────────────
        identity = check_process_identity(pid, exe, float(create_ts))

        if identity == CheckIdentityResult.UNKNOWN:
            # Access denied or query error — process may be alive, cannot confirm
            failures.append(
                f"Session {s_file.name}: PID={pid} identity check returned UNKNOWN "
                "(access denied or query error) — aborting upgrade, session preserved"
            )
            continue

        if identity == CheckIdentityResult.GONE:
            # Process definitely no longer running — safe to remove stale record
            s_file.unlink(missing_ok=True)
            continue

        if identity == CheckIdentityResult.UNMATCHED:
            # PID recycled by a different process — delete stale record, do NOT kill
            s_file.unlink(missing_ok=True)
            continue

        # identity == MATCHED — attempt verified graceful + force termination
        stopped = terminate_process(pid, exe, float(create_ts), timeout_sec=timeout_sec)
        if not stopped:
            failures.append(
                f"Failed to stop session PID={pid} exe={exe}: "
                f"process still alive after {timeout_sec}s — aborting upgrade, session preserved"
            )
            # Leave session file intact
            continue

        # Confirmed stopped — safe to remove session record
        s_file.unlink(missing_ok=True)

    if failures:
        return False, "; ".join(failures)
    return True, ""


def get_default_install_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "Programs" / "ProDocuX" / "LocalAI"
    return Path.home() / "AppData" / "Local" / "Programs" / "ProDocuX" / "LocalAI"


def get_default_profile_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "ProDocuX" / "LocalAI" / "profiles" / "default"
    return Path.home() / "AppData" / "Local" / "ProDocuX" / "LocalAI" / "profiles" / "default"


class Installer:
    def __init__(self, target_dir: Path, profile_dir: Path) -> None:
        self.target_dir = target_dir.resolve()
        self.profile_dir = profile_dir.resolve()
        self.manifest_path = self.target_dir / "install-manifest.json"

    def install(self, dist_source_dir: Path, version: str = "0.0.1", *,
                accept_windows_runtime_terms: bool = False) -> tuple[bool, str]:
        dist_source = dist_source_dir.resolve()
        if not dist_source.exists():
            return False, f"Distribution source directory does not exist: {dist_source}"

        exe_source = dist_source / "pdx-local.exe"
        if not exe_source.exists():
            return False, f"pdx-local.exe not found in distribution directory: {dist_source}"

        terms_digest = None
        if sys.platform == 'win32':
            from pdx_local_ai.windows_runtime_terms import terms_info
            if not accept_windows_runtime_terms:
                return False, ('Windows runtime terms require explicit acceptance. '
                               'Review WINDOWS-RUNTIME-TERMS.txt, then pass '
                               '--accept-windows-runtime-terms.')
            try:
                _, terms_digest = terms_info(dist_source / '_internal' / 'windows-runtime' / 'WINDOWS-RUNTIME-TERMS.txt')
                _, current_digest = terms_info()
                if terms_digest != current_digest:
                    return False, 'Source and installer Windows runtime terms differ'
                if not (dist_source / '_internal' / 'windows-runtime' / 'THIRD-PARTY-NOTICES.txt').is_file():
                    return False, 'Bundled third-party notices unavailable'
            except (OSError, ValueError) as exc:
                return False, f'Windows runtime terms unavailable: {exc}'

        self.target_dir.parent.mkdir(parents=True, exist_ok=True)
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        lock_file = self.profile_dir / "maintenance.lock"

        # Continuous maintenance lock spanning shutdown → install → migration
        lock = CrossProcessMaintenanceLock(lock_file)
        if not lock.acquire(timeout_sec=5.0):
            return False, f"Could not acquire exclusive maintenance lock on {lock_file}. Is pdx-local running?"

        old_dir: Path | None = None
        is_upgrade = self.target_dir.exists()
        migration_marker = self.profile_dir / MIGRATION_FAILED_MARKER

        try:
            # 1. Stop all active sessions — ABORT if any session cannot be stopped
            ok, fail_reason = stop_active_sessions(self.profile_dir)
            if not ok:
                return False, f"Upgrade aborted: Could not stop all active sessions. {fail_reason}"

            # Clear previous migration failure marker (we are attempting fresh upgrade)
            migration_marker.unlink(missing_ok=True)

            # 2. Backup catalog via sqlite3.Connection.backup() if upgrading
            cat_db = self.profile_dir / "catalog.sqlite"
            backup_created: Path | None = None
            if cat_db.exists():
                backup_dir = self.profile_dir / "backups"
                backup_dir.mkdir(parents=True, exist_ok=True)
                backup_dest = backup_dir / f"catalog_backup_pre_upgrade_{int(time.time())}.sqlite"
                src_conn = sqlite3.connect(str(cat_db))
                dest_conn = sqlite3.connect(str(backup_dest))
                try:
                    src_conn.backup(dest_conn)
                    dest_conn.commit()
                    integrity = [str(r[0]) for r in dest_conn.execute("PRAGMA integrity_check")]
                    if integrity != ["ok"]:
                        backup_dest.unlink(missing_ok=True)
                        return False, f"Backup integrity verification failed: {integrity}"
                    backup_created = backup_dest
                finally:
                    src_conn.close()
                    dest_conn.close()

            # 2b. Back up the task database (tasks.sqlite) the same way; it is migrated below.
            tasks_db = self.profile_dir / "tasks.sqlite"
            if tasks_db.exists():
                backup_dir = self.profile_dir / "backups"
                backup_dir.mkdir(parents=True, exist_ok=True)
                tasks_backup = backup_dir / f"tasks_backup_pre_upgrade_{int(time.time())}.sqlite"
                t_src = sqlite3.connect(str(tasks_db))
                t_dest = sqlite3.connect(str(tasks_backup))
                try:
                    t_src.backup(t_dest)
                    t_dest.commit()
                    t_integrity = [str(r[0]) for r in t_dest.execute("PRAGMA integrity_check")]
                    if t_integrity != ["ok"]:
                        tasks_backup.unlink(missing_ok=True)
                        return False, f"Task database backup integrity verification failed: {t_integrity}"
                finally:
                    t_src.close()
                    t_dest.close()

            # 3. Stage new binaries
            staging_dir = self.target_dir.parent / f"{self.target_dir.name}.staging.{os.getpid()}_{int(time.time())}"
            if staging_dir.exists():
                shutil.rmtree(staging_dir)
            staging_dir.mkdir(parents=True, exist_ok=True)

            installed_files: dict[str, dict[str, Any]] = {}
            for item in dist_source.rglob("*"):
                if item.is_file():
                    rel = item.relative_to(dist_source)
                    dest_file = staging_dir / rel
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, dest_file)
                    installed_files[str(rel).replace("\\", "/")] = {
                        "size_bytes": dest_file.stat().st_size,
                        "sha256": _sha256(dest_file),
                    }

            if terms_digest is not None:
                from pdx_local_ai.windows_runtime_terms import RECORD_FILE, write_acceptance
                # Do not inherit acceptance from a copied build or prior install.
                # This is new staging owned by the current install operation.
                (staging_dir / RECORD_FILE).unlink(missing_ok=True)
                write_acceptance(staging_dir, terms_digest, version, 'explicit_installer_flag')
                installed_files[RECORD_FILE] = {
                    'size_bytes': (staging_dir / RECORD_FILE).stat().st_size,
                    'sha256': _sha256(staging_dir / RECORD_FILE),
                }

            manifest_data = {
                "schema_version": "pdx_local_install_manifest_v1",
                "product_name": "pdx-local-ai",
                "version": version,
                "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "target_directory": str(self.target_dir),
                "installed_files": installed_files,
            }
            (staging_dir / "install-manifest.json").write_text(
                json.dumps(manifest_data, indent=2), encoding="utf-8"
            )

            # 4. Atomic directory swap — old_dir is KEPT until migration validation succeeds
            if is_upgrade:
                old_dir = self.target_dir.parent / f"{self.target_dir.name}.old.{os.getpid()}_{int(time.time())}"
                if old_dir.exists():
                    shutil.rmtree(old_dir, ignore_errors=True)
                try:
                    os.replace(self.target_dir, old_dir)
                except Exception as exc:
                    shutil.rmtree(staging_dir, ignore_errors=True)
                    return False, f"Failed to move existing installation to old directory: {exc}"

            try:
                os.replace(staging_dir, self.target_dir)
            except Exception as exc:
                if old_dir and old_dir.exists():
                    os.replace(old_dir, self.target_dir)
                shutil.rmtree(staging_dir, ignore_errors=True)
                return False, f"Staged directory replacement failed, rolled back: {exc}"

            # 5. Database Schema Migration using the PRODUCT migration pipeline.
            #
            # Note on in-process apply_migrations():
            #   The installer is a PyInstaller frozen binary (pdx-local.exe). When a new
            #   version is installed, the CURRENT running installer process already contains
            #   the NEW version's code (it IS the new binary). apply_migrations() therefore
            #   runs the new version's migration logic — this is correct for the upgrade path.
            #   The old binary has already been moved to old_dir at this point; target_dir now
            #   contains the new binaries. In-process migration is equivalent to running the
            #   new binary's migration entrypoint for the frozen-binary delivery model.
            #   A subprocess entrypoint (pdx-local.exe installer migrate) would be needed
            #   only if the installer binary itself were *different* from the product binary,
            #   which is not the case in this delivery model.
            if cat_db.exists() or tasks_db.exists():
                migration_exc: Exception | None = None
                try:
                    if cat_db.exists():
                        from pdx_local_ai.catalog import apply_migrations
                        conn = sqlite3.connect(str(cat_db))
                        conn.execute("PRAGMA journal_mode=WAL")
                        conn.execute("PRAGMA busy_timeout=5000")
                        try:
                            apply_migrations(conn)
                        finally:
                            conn.close()
                    if tasks_db.exists():
                        # Same pipeline and rollback path: a task DB migration failure restores the
                        # old binaries and writes MIGRATION_FAILED; the original DB and backup stay.
                        from pdx_local_ai.tasks.store import migrate_tasks_database
                        migrate_tasks_database(tasks_db)
                except Exception as exc:
                    migration_exc = exc

                if migration_exc is not None:
                    # ── Migration failed: attempt to restore old binary directory ──────
                    restore_errors: list[str] = []
                    if old_dir and old_dir.exists():
                        try:
                            os.replace(self.target_dir, staging_dir)  # park new aside
                            os.replace(old_dir, self.target_dir)       # restore old
                        except Exception as restore_exc:
                            restore_errors.append(
                                f"CRITICAL: Failed to restore old binary directory: {restore_exc}. "
                                f"Both {self.target_dir} and {old_dir} may be in an inconsistent state."
                            )

                    # ── Write persistent migration failure marker ─────────────────────
                    marker_errors: list[str] = []
                    try:
                        migration_marker.write_text(
                            json.dumps({
                                "failed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                "reason": str(migration_exc),
                                "backup_path": str(backup_created) if backup_created else None,
                                "restore_errors": restore_errors,
                            }),
                            encoding="utf-8",
                        )
                    except Exception as marker_exc:
                        marker_errors.append(
                            f"CRITICAL: Failed to write MIGRATION_FAILED marker: {marker_exc}. "
                            "Service startup will NOT be blocked automatically — manual intervention required."
                        )

                    # Build full failure message — every error is surfaced, nothing swallowed
                    parts: list[str] = [
                        f"Database migration failed: {migration_exc}.",
                        f"Original database and backup at {backup_created} were preserved.",
                    ]
                    parts.extend(restore_errors)
                    parts.extend(marker_errors)
                    if not restore_errors:
                        parts.append(f"Old binaries restored to {self.target_dir}.")
                    if not marker_errors:
                        parts.append(f"Migration failure marker written to {migration_marker}.")
                    return False, " ".join(parts)

            # 6. Migration succeeded — safe to remove old binary directory
            if old_dir and old_dir.exists():
                shutil.rmtree(old_dir, ignore_errors=True)

        finally:
            lock.release()

        action_str = "upgraded" if is_upgrade else "installed"
        return True, f"Successfully {action_str} ProDocuX Local AI (v{version}) into {self.target_dir}"

    def uninstall(self, purge_data: bool = False) -> tuple[bool, str]:
        if not self.target_dir.exists():
            return True, f"Target directory {self.target_dir} does not exist. Nothing to uninstall."

        lock_file = self.profile_dir / "maintenance.lock"
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        lock = CrossProcessMaintenanceLock(lock_file)
        if not lock.acquire(timeout_sec=5.0):
            return False, f"Could not acquire maintenance lock on {lock_file}. Is a session running?"

        try:
            # 1. Stop any active sessions
            ok, fail_reason = stop_active_sessions(self.profile_dir)
            if not ok:
                return False, f"Uninstall aborted: Could not stop all active sessions. {fail_reason}"

            # 2. Validate manifest fail-closed
            if not self.manifest_path.exists():
                return False, (
                    f"Install manifest not found at {self.manifest_path}. "
                    "Refusing to delete unknown directory contents."
                )

            try:
                manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            except Exception as exc:
                return False, f"Failed to parse install manifest at {self.manifest_path}: {exc}. Refusing to delete."

            files = manifest.get("installed_files")
            if not isinstance(files, dict):
                return False, "Invalid manifest format: 'installed_files' missing or malformed."

            # Verify all paths against directory traversal before deleting anything
            paths_to_delete: list[Path] = []
            for rel_str in files.keys():
                rel = Path(rel_str)
                if rel.is_absolute() or ".." in rel.parts:
                    return False, f"Security violation: Manifest path '{rel_str}' contains directory traversal!"
                abs_p = (self.target_dir / rel).resolve()
                try:
                    abs_p.relative_to(self.target_dir)
                except ValueError:
                    return False, (
                        f"Security violation: Manifest path '{rel_str}' escapes target directory {self.target_dir}!"
                    )
                paths_to_delete.append(abs_p)

            # Delete tracked files only
            for p in paths_to_delete:
                p.unlink(missing_ok=True)
            self.manifest_path.unlink(missing_ok=True)
            (self.target_dir / "uninstall.ps1").unlink(missing_ok=True)

            # Remove target_dir only if no untracked files remain
            remaining_files = [p for p in self.target_dir.rglob("*") if p.is_file()]
            if not remaining_files:
                shutil.rmtree(self.target_dir, ignore_errors=True)

            # 3. Handle user profile data (Fail-Closed)
            if purge_data and self.profile_dir.exists():
                db_path = self.profile_dir / "catalog.sqlite"
                if db_path.exists():
                    try:
                        conn = sqlite3.connect(str(db_path))
                        rows = conn.execute("SELECT canonical_path FROM source_root").fetchall()
                        conn.close()
                    except Exception as exc:
                        return False, (
                            f"Fail-closed refusal: Could not inspect source roots from {db_path}: {exc}. "
                            "Profile was NOT deleted."
                        )

                    # Check ALL 3 overlap directions
                    for r in rows:
                        src_p = Path(str(r[0])).resolve()
                        if (
                            self.profile_dir == src_p
                            or src_p in self.profile_dir.parents
                            or self.profile_dir in src_p.parents
                        ):
                            return False, (
                                f"Safety violation: Profile directory {self.profile_dir} overlaps with "
                                f"document source root {src_p}! Purge aborted."
                            )

                # Check recursive junctions and symlinks across profile_dir
                for p in [self.profile_dir, *self.profile_dir.rglob("*")]:
                    if _is_reparse_or_symlink(p):
                        return False, (
                            f"Safety violation: Path {p} inside profile is a reparse point or symlink! "
                            "Purge aborted."
                        )

                shutil.rmtree(self.profile_dir)

        finally:
            lock.release()

        data_msg = (
            "User profile data was purged."
            if purge_data
            else f"User profile data at {self.profile_dir} was preserved."
        )
        return True, f"Successfully uninstalled ProDocuX Local AI from {self.target_dir}. {data_msg}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pdx-installer", description="ProDocuX Local AI Windows Installer Shell")
    sub = parser.add_subparsers(dest="command")

    p_install = sub.add_parser("install", help="Install or upgrade pdx-local")
    p_install.add_argument("--source-dist", required=True)
    p_install.add_argument("--target-dir")
    p_install.add_argument("--profile-dir")
    p_install.add_argument("--version", default="0.0.1")
    p_install.add_argument("--accept-windows-runtime-terms", action="store_true")

    p_uninstall = sub.add_parser("uninstall", help="Uninstall pdx-local")
    p_uninstall.add_argument("--target-dir")
    p_uninstall.add_argument("--profile-dir")
    p_uninstall.add_argument("--purge-data", action="store_true")

    args = parser.parse_args(argv)
    target_dir = Path(args.target_dir) if args.target_dir else get_default_install_dir()
    profile_dir = Path(args.profile_dir) if args.profile_dir else get_default_profile_dir()
    installer = Installer(target_dir, profile_dir)

    if args.command == "install":
        ok, msg = installer.install(Path(args.source_dist), version=args.version,
                                   accept_windows_runtime_terms=args.accept_windows_runtime_terms)
        if ok:
            sys.stdout.write(f"[SUCCESS] {msg}\n")
            return 0
        sys.stderr.write(f"[ERROR] {msg}\n")
        return 1

    if args.command == "uninstall":
        ok, msg = installer.uninstall(purge_data=args.purge_data)
        if ok:
            sys.stdout.write(f"[SUCCESS] {msg}\n")
            return 0
        sys.stderr.write(f"[ERROR] {msg}\n")
        return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
