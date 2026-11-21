"""ProDocuX Local AI unified CLI management entry point (pdx-local).

Subcommands:
- init: Initialize a profile directory and catalog.sqlite (fail-safe if exists).
- source add <path>: Register a source directory root.
- source list: List all registered source roots.
- source scan <root-id>: Scan and index a source root.
- agent config cursor: Generate or apply Cursor MCP configuration.
- agent config preview: Print the same service entry for Cursor, Claude, Codex, or Antigravity.
- purge: Safely delete profile user data while verifying no source directory overlap.
- status: Display profile health, schema version, and index statistics.
- service: Run MCP stdio server transport.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import uuid
from pathlib import Path
from typing import Any

from pdx_local_ai.catalog import Catalog, CURRENT_SCHEMA_VERSION
from pdx_local_ai.agent_config import MCP_CLIENTS, generate_agent_mcp_config, merge_cursor_mcp_config, render_mcp_snippet
from pdx_local_ai.service.stdio_transport import main as service_main
from pdx_local_ai.validation import ContractError


def get_default_profile_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "ProDocuX" / "LocalAI" / "profiles" / "default"
    return Path.home() / ".prodocux" / "local-ai" / "profiles" / "default"


def cmd_init(args: argparse.Namespace) -> int:
    profile_dir = Path(args.profile_dir).resolve() if args.profile_dir else get_default_profile_dir()
    db_path = profile_dir / "catalog.sqlite"
    cfg_path = profile_dir / "config.json"

    if db_path.exists() or cfg_path.exists():
        sys.stderr.write(f"[ERROR] Profile already exists at {profile_dir}. Refusing to overwrite.\n")
        return 1

    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "run" / "sessions").mkdir(parents=True, exist_ok=True)
    (profile_dir / "logs").mkdir(parents=True, exist_ok=True)

    ws_id = args.workspace_id or str(uuid.uuid4())
    default_principal = args.principal_id or "default-user"

    cfg_data = {
        "schema_version": "pdx_local_profile_config_v1",
        "workspace_id": ws_id,
        "default_principal_id": default_principal,
        "profile_dir": str(profile_dir),
        "catalog_db": str(db_path),
    }
    cfg_path.write_text(json.dumps(cfg_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    cat = Catalog(db_path)
    cat.close()

    sys.stdout.write(f"[SUCCESS] Profile successfully initialized at: {profile_dir}\n")
    sys.stdout.write(f"Workspace ID: {ws_id}\n")
    sys.stdout.write(f"Default Principal: {default_principal}\n")
    return 0


def cmd_source_add(args: argparse.Namespace) -> int:
    profile_dir = Path(args.profile_dir).resolve() if args.profile_dir else get_default_profile_dir()
    db_path = Path(args.catalog_path).resolve() if args.catalog_path else profile_dir / "catalog.sqlite"
    if not db_path.exists():
        sys.stderr.write(f"[ERROR] Catalog database not found at {db_path}. Run 'init' first.\n")
        return 1

    cfg_path = profile_dir / "config.json"
    ws_id = args.workspace_id
    if not ws_id and cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            ws_id = cfg.get("workspace_id")
        except Exception:
            pass
    if not ws_id:
        ws_id = str(uuid.uuid4())

    inherit_principal = args.principal_id if args.inherit_read else None

    cat = Catalog(db_path)
    try:
        root_id = cat.add_root(
            workspace_id=ws_id,
            canonical_path=str(Path(args.path).resolve()),
            inherit_read_principal=inherit_principal,
        )
        sys.stdout.write(f"[SUCCESS] Source root added:\n")
        sys.stdout.write(f"  Root ID: {root_id}\n")
        sys.stdout.write(f"  Path: {Path(args.path).resolve()}\n")
        sys.stdout.write(f"  Inherited Principal: {inherit_principal}\n")
        return 0
    except Exception as exc:
        sys.stderr.write(f"[ERROR] Failed to add source root: {exc}\n")
        return 1
    finally:
        cat.close()


def cmd_source_list(args: argparse.Namespace) -> int:
    profile_dir = Path(args.profile_dir).resolve() if args.profile_dir else get_default_profile_dir()
    db_path = Path(args.catalog_path).resolve() if args.catalog_path else profile_dir / "catalog.sqlite"
    if not db_path.exists():
        sys.stderr.write(f"[ERROR] Catalog database not found at {db_path}.\n")
        return 1

    cat = Catalog(db_path)
    try:
        rows = cat.conn.execute("SELECT source_root_id, workspace_id, canonical_path, enabled, config_json FROM source_root").fetchall()
        if not rows:
            sys.stdout.write("No source roots configured.\n")
            return 0
        sys.stdout.write(f"Configured Source Roots ({len(rows)}):\n")
        for r in rows:
            cfg = json.loads(r["config_json"])
            inherit = cfg.get("inherit_read_principal", "None")
            status_str = "enabled" if r["enabled"] else "disabled"
            sys.stdout.write(f"- ID: {r['source_root_id']}\n")
            sys.stdout.write(f"  Path: {r['canonical_path']} [{status_str}]\n")
            sys.stdout.write(f"  Inherit Read: {inherit}\n")
        return 0
    finally:
        cat.close()


def cmd_source_scan(args: argparse.Namespace) -> int:
    profile_dir = Path(args.profile_dir).resolve() if args.profile_dir else get_default_profile_dir()
    db_path = Path(args.catalog_path).resolve() if args.catalog_path else profile_dir / "catalog.sqlite"
    if not db_path.exists():
        sys.stderr.write(f"[ERROR] Catalog database not found at {db_path}.\n")
        return 1

    cat = Catalog(db_path)
    try:
        counts = cat.scan(source_root_id=args.root_id, raise_on_error=True)
        sys.stdout.write(f"[SUCCESS] Scan completed for root {args.root_id}:\n")
        for k, v in counts.items():
            sys.stdout.write(f"  {k}: {v}\n")
        return 0
    except Exception as exc:
        sys.stderr.write(f"[ERROR] Scan failed: {exc}\n")
        return 1
    finally:
        cat.close()


def cmd_agent_config_cursor(args: argparse.Namespace) -> int:
    profile_dir = Path(args.profile_dir).resolve() if args.profile_dir else get_default_profile_dir()
    db_path = Path(args.catalog_path).resolve() if args.catalog_path else profile_dir / "catalog.sqlite"
    cfg_path = profile_dir / "config.json"

    ws_id = args.workspace_id
    principal = args.principal_id
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            if not ws_id:
                ws_id = cfg.get("workspace_id")
            if not principal:
                principal = cfg.get("default_principal_id")
        except Exception:
            pass

    if not ws_id or not principal:
        sys.stderr.write("[ERROR] workspace-id and principal-id must be specified or present in config.json.\n")
        return 1

    root_id = args.scheduled_root_id
    if not root_id and db_path.exists():
        cat = Catalog(db_path)
        try:
            r = cat.conn.execute("SELECT source_root_id FROM source_root WHERE enabled=1 LIMIT 1").fetchone()
            if r:
                root_id = str(r[0])
        finally:
            cat.close()

    if not root_id:
        sys.stderr.write("[ERROR] No scheduled-root-id provided and no enabled source root found in catalog.\n")
        return 1

    binary_path = args.binary_path or sys.executable

    server_cfg = generate_agent_mcp_config(
        binary_path=binary_path,
        catalog_path=str(db_path),
        workspace_id=ws_id,
        principal_id=principal,
        scheduled_root_id=root_id,
        poll_interval_sec=args.poll_interval_sec,
        allow_agent_refresh=args.allow_agent_refresh,
    )

    client = getattr(args, "client", "cursor")
    try:
        preview = render_mcp_snippet(client, server_cfg)
    except ValueError as exc:
        sys.stderr.write(f"[ERROR] {exc}\n")
        return 1

    if not args.apply:
        sys.stdout.write(preview)
        sys.stderr.write(
            "\n[INFO] Configuration preview generated to stdout.\n"
            "[INFO] --apply writes only the Cursor mcp.json. Other clients paste this preview themselves.\n"
        )
        return 0
    if client != "cursor":
        sys.stderr.write("[ERROR] --apply only writes Cursor mcp.json. Omit --apply to preview another client.\n")
        return 1

    target = Path(args.target_mcp_json) if args.target_mcp_json else Path.home() / ".cursor" / "mcp.json"
    ok, msg = merge_cursor_mcp_config(target, "pdx-local-ai", server_cfg, force=args.force)
    if not ok:
        sys.stderr.write(f"[ERROR] {msg}\n")
        return 1
    sys.stderr.write(f"[SUCCESS] {msg}\n")
    return 0


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        info = os.lstat(path)
        is_reparse = bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return is_reparse or stat.S_ISLNK(info.st_mode)
    except Exception:
        return False


def cmd_purge(args: argparse.Namespace) -> int:
    profile_dir = Path(args.profile_dir).resolve() if args.profile_dir else get_default_profile_dir()
    if not profile_dir.exists():
        sys.stdout.write(f"Profile directory {profile_dir} does not exist. Nothing to purge.\n")
        return 0

    db_path = profile_dir / "catalog.sqlite"
    if db_path.exists():
        try:
            cat = Catalog(db_path)
            rows = cat.conn.execute("SELECT canonical_path FROM source_root").fetchall()
            roots = [Path(str(r[0])).resolve() for r in rows]
            cat.close()

            # Source protection guard: verify profile directory does NOT overlap in ANY direction
            for r in roots:
                if profile_dir == r or r in profile_dir.parents or profile_dir in r.parents:
                    sys.stderr.write(f"[CRITICAL ERROR] Refusing purge! Profile directory {profile_dir} overlaps with source root {r}!\n")
                    return 2
        except Exception as exc:
            # Strictly Fail-Closed: no bypass permitted
            sys.stderr.write(f"[ERROR] Fail-closed safety refusal: Could not inspect catalog for source roots: {exc}. Refusing to purge.\n")
            return 1

    # Check for symlink / reparse point recursively across profile directory
    for p in [profile_dir, *profile_dir.rglob("*")]:
        if _is_reparse_or_symlink(p):
            sys.stderr.write(f"[ERROR] Refusing purge: Path {p} is a symlink or reparse point.\n")
            return 1

    # Safely remove profile contents
    try:
        shutil.rmtree(profile_dir)
        sys.stdout.write(f"[SUCCESS] Safely purged profile directory: {profile_dir}\n")
        return 0
    except Exception as exc:
        sys.stderr.write(f"[ERROR] Failed to purge profile: {exc}\n")
        return 1


def cmd_installer_install(args: argparse.Namespace) -> int:
    from pdx_local_ai.installer import Installer, get_default_install_dir, get_default_profile_dir
    target_dir = Path(args.target_dir) if args.target_dir else get_default_install_dir()
    profile_dir = Path(args.profile_dir) if args.profile_dir else get_default_profile_dir()
    installer = Installer(target_dir, profile_dir)
    ok, msg = installer.install(Path(args.source_dist), version=args.version,
                               accept_windows_runtime_terms=args.accept_windows_runtime_terms)
    if ok:
        sys.stdout.write(f"[SUCCESS] {msg}\n")
        return 0
    sys.stderr.write(f"[ERROR] {msg}\n")
    return 1


def cmd_installer_uninstall(args: argparse.Namespace) -> int:
    from pdx_local_ai.installer import Installer, get_default_install_dir, get_default_profile_dir
    target_dir = Path(args.target_dir) if args.target_dir else get_default_install_dir()
    profile_dir = Path(args.profile_dir) if args.profile_dir else get_default_profile_dir()
    installer = Installer(target_dir, profile_dir)
    ok, msg = installer.uninstall(purge_data=args.purge_data)
    if ok:
        sys.stdout.write(f"[SUCCESS] {msg}\n")
        return 0
    sys.stderr.write(f"[ERROR] {msg}\n")
    return 1


def cmd_service(args: argparse.Namespace) -> int:
    from pdx_local_ai.maintenance_lock import CrossProcessMaintenanceLock
    cat_path = Path(args.catalog_path).resolve()
    profile_dir = cat_path.parent
    lock_file = profile_dir / "maintenance.lock"
    if CrossProcessMaintenanceLock.is_locked(lock_file):
        sys.stderr.write(
            f"[CRITICAL ERROR] Service startup refused: Profile directory {profile_dir} is locked for maintenance "
            f"(installation or upgrade in progress). Exiting.\n"
        )
        return 4

    from pdx_local_ai.service.stdio_transport import run_stdio_server, resolve_trusted_security_context
    sec_ctx = resolve_trusted_security_context(sys.argv[1:])
    return run_stdio_server(
        catalog_path=cat_path,
        security_context=sec_ctx,
        refresh_policy=args.refresh_policy,
        poll_interval_sec=args.poll_interval_sec,
        stale_ttl_sec=args.stale_ttl_sec,
        scheduled_refresh_roots=[args.scheduled_refresh_root] if args.scheduled_refresh_root else None,
        shutdown_timeout_sec=args.shutdown_timeout_sec,
    )


def cmd_status(args: argparse.Namespace) -> int:
    profile_dir = Path(args.profile_dir).resolve() if args.profile_dir else get_default_profile_dir()
    db_path = Path(args.catalog_path).resolve() if args.catalog_path else profile_dir / "catalog.sqlite"

    sys.stdout.write(f"ProDocuX Local AI Status\n")
    sys.stdout.write(f"Profile Dir: {profile_dir} (exists={profile_dir.exists()})\n")
    sys.stdout.write(f"Catalog Path: {db_path} (exists={db_path.exists()})\n")

    if not db_path.exists():
        return 0

    try:
        cat = Catalog(db_path)
        ver = cat.conn.execute("PRAGMA user_version").fetchone()[0]
        roots_count = cat.conn.execute("SELECT COUNT(*) FROM source_root").fetchone()[0]
        files_count = cat.conn.execute("SELECT COUNT(*) FROM file_record WHERE catalog_status='active'").fetchone()[0]
        sys.stdout.write(f"Schema Version: {ver} (current binary supports {CURRENT_SCHEMA_VERSION})\n")
        sys.stdout.write(f"Active Source Roots: {roots_count}\n")
        sys.stdout.write(f"Active Files: {files_count}\n")
        cat.close()
        return 0
    except Exception as exc:
        sys.stderr.write(f"[ERROR] Failed to query status: {exc}\n")
        return 1


def cmd_task(args: argparse.Namespace) -> int:
    """Human operator channel for the task harness (approve / review / inspect / purge).

    The CLI is the local trusted operator path: it carries approver and reviewer capability,
    which MCP agent connections only receive when the host explicitly grants it.
    """
    from pdx_local_ai.service.contracts import SecurityContext, ServiceError
    from pdx_local_ai.tasks.service import TaskService
    from pdx_local_ai.tasks.store import TASKS_DB_NAME

    profile_dir = Path(args.profile_dir).resolve() if args.profile_dir else get_default_profile_dir()
    cfg_path = profile_dir / "config.json"
    ws_id, principal = args.workspace_id, args.principal_id
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            ws_id = ws_id or cfg.get("workspace_id")
            principal = principal or cfg.get("default_principal_id")
        except Exception:
            pass
    if not ws_id or not principal:
        sys.stderr.write("[ERROR] workspace-id and principal-id must be specified or present in config.json.\n")
        return 1
    if not (profile_dir / TASKS_DB_NAME).exists():
        sys.stdout.write(json.dumps({"tasks": [], "note": "no task database in this profile"}) + "\n")
        return 0
    ctx = SecurityContext(workspace_id=ws_id, principal_id=principal, is_admin=True,
                          can_approve_tasks=True, can_review_tasks=True, actor_kind="human_cli")
    service = TaskService.open(profile_dir, run_recovery=False, engine_required=False)
    try:
        cmd = args.task_cmd
        if cmd == "list":
            out = service.list_tasks(ctx, states=args.state or None, limit=args.limit)
        elif cmd == "show":
            out = service.get_task(ctx, args.task_id)
        elif cmd == "events":
            out = service.get_task_events(ctx, args.task_id, after_seq=args.after_seq, limit=args.limit)
        elif cmd == "approve":
            out = service.approve_task(ctx, args.task_id)
        elif cmd == "revoke":
            out = service.revoke_task_approval(ctx, args.task_id)
        elif cmd == "cancel":
            out = service.cancel_task(ctx, args.task_id, args.reason)
        elif cmd == "review":
            out = service.review_task_result(ctx, args.task_id, args.decision, step_id=args.step_id, note=args.note)
        elif cmd == "purge-expired":
            out = service.purge_expired(ctx)
        else:  # pragma: no cover
            return 1
        sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
        return 0
    except ServiceError as exc:
        sys.stderr.write(f"[ERROR] {exc}\n")
        return 1
    finally:
        service.store.close()


def cmd_terms(args: argparse.Namespace) -> int:
    from pdx_local_ai.windows_runtime_terms import accept_portable, terms_info
    if args.terms_cmd == 'show':
        text, digest = terms_info()
        sys.stdout.write(text + '\nSHA-256: ' + digest + '\n')
    else:
        accept_portable(args.terms_sha256, args.accept_windows_runtime_terms)
        sys.stdout.write('Windows runtime terms acceptance recorded locally.\n')
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pdx-local", description="ProDocuX Local AI Management CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    p_terms = subparsers.add_parser('terms', help='Read/accept Windows bundled runtime conditions')
    terms_sub = p_terms.add_subparsers(dest='terms_cmd', required=True)
    p_show = terms_sub.add_parser('show')
    p_show.set_defaults(func=cmd_terms)
    p_accept = terms_sub.add_parser('accept')
    p_accept.add_argument('--terms-sha256', required=True)
    p_accept.add_argument('--accept-windows-runtime-terms', action='store_true')
    p_accept.set_defaults(func=cmd_terms)

    # init
    p_init = subparsers.add_parser("init", help="Initialize profile directory and catalog database")
    p_init.add_argument("--profile-dir", help="Custom profile directory")
    p_init.add_argument("--workspace-id", help="Workspace UUID")
    p_init.add_argument("--principal-id", help="Default principal ID")
    p_init.set_defaults(func=cmd_init)

    # source
    p_source = subparsers.add_parser("source", help="Manage source directory roots")
    source_sub = p_source.add_subparsers(dest="source_cmd", help="Source actions")

    p_s_add = source_sub.add_parser("add", help="Add a source directory")
    p_s_add.add_argument("path", help="Local directory path")
    p_s_add.add_argument("--workspace-id", help="Workspace UUID")
    p_s_add.add_argument("--principal-id", help="Principal identity")
    p_s_add.add_argument("--inherit-read", action="store_true", help="Automatically grant read access to principal for scanned files")
    p_s_add.add_argument("--profile-dir", help="Custom profile directory")
    p_s_add.add_argument("--catalog-path", help="Custom catalog sqlite path")
    p_s_add.set_defaults(func=cmd_source_add)

    p_s_list = source_sub.add_parser("list", help="List configured source directories")
    p_s_list.add_argument("--profile-dir", help="Custom profile directory")
    p_s_list.add_argument("--catalog-path", help="Custom catalog sqlite path")
    p_s_list.set_defaults(func=cmd_source_list)

    p_s_scan = source_sub.add_parser("scan", help="Scan a source directory root")
    p_s_scan.add_argument("root_id", help="Source root ID")
    p_s_scan.add_argument("--profile-dir", help="Custom profile directory")
    p_s_scan.add_argument("--catalog-path", help="Custom catalog sqlite path")
    p_s_scan.set_defaults(func=cmd_source_scan)

    # agent config
    p_agent = subparsers.add_parser("agent", help="Agent integrations")
    agent_sub = p_agent.add_subparsers(dest="agent_cmd")
    p_ag_cfg = agent_sub.add_parser("config", help="Generate agent configuration")
    ag_cfg_sub = p_ag_cfg.add_subparsers(dest="client_kind")
    p_cursor = ag_cfg_sub.add_parser("cursor", help="Generate Cursor MCP configuration")
    p_cursor.add_argument("--binary-path", help="Path to pdx-local binary")
    p_cursor.add_argument("--catalog-path", help="Path to catalog sqlite")
    p_cursor.add_argument("--profile-dir", help="Custom profile directory")
    p_cursor.add_argument("--workspace-id", help="Workspace UUID")
    p_cursor.add_argument("--principal-id", help="Principal identity")
    p_cursor.add_argument("--scheduled-root-id", help="Source root ID for background scan")
    p_cursor.add_argument("--poll-interval-sec", type=float, default=2.0)
    p_cursor.add_argument("--allow-agent-refresh", action="store_true")
    p_cursor.add_argument("--apply", action="store_true", help="Apply to Cursor mcp.json")
    p_cursor.add_argument("--target-mcp-json", help="Custom mcp.json location")
    p_cursor.add_argument("--force", action="store_true", help="Force overwrite conflicting entry")
    p_cursor.set_defaults(func=cmd_agent_config_cursor, client="cursor")
    p_preview = ag_cfg_sub.add_parser("preview", help="Print an MCP snippet for one client")
    p_preview.add_argument("--client", required=True, choices=MCP_CLIENTS)
    p_preview.add_argument("--binary-path", help="Path to pdx-local binary")
    p_preview.add_argument("--catalog-path", help="Path to catalog sqlite")
    p_preview.add_argument("--profile-dir", help="Custom profile directory")
    p_preview.add_argument("--workspace-id", help="Workspace UUID")
    p_preview.add_argument("--principal-id", help="Principal identity")
    p_preview.add_argument("--scheduled-root-id", help="Source root ID for background scan")
    p_preview.add_argument("--poll-interval-sec", type=float, default=2.0)
    p_preview.add_argument("--allow-agent-refresh", action="store_true")
    p_preview.set_defaults(func=cmd_agent_config_cursor, apply=False)

    # purge
    p_purge = subparsers.add_parser("purge", help="Safely purge profile data")
    p_purge.add_argument("--profile-dir", help="Custom profile directory")
    p_purge.set_defaults(func=cmd_purge)

    # installer
    p_inst = subparsers.add_parser("installer", help="Manage installation and uninstallation")
    inst_sub = p_inst.add_subparsers(dest="installer_cmd")

    p_in_install = inst_sub.add_parser("install", help="Install or upgrade pdx-local")
    p_in_install.add_argument("--source-dist", required=True, help="Path to distribution folder")
    p_in_install.add_argument("--target-dir", help="Installation target folder")
    p_in_install.add_argument("--profile-dir", help="Profile folder")
    p_in_install.add_argument("--version", default="0.0.1", help="Version")
    p_in_install.add_argument('--accept-windows-runtime-terms', action='store_true')
    p_in_install.set_defaults(func=cmd_installer_install)

    p_in_uninst = inst_sub.add_parser("uninstall", help="Uninstall pdx-local")
    p_in_uninst.add_argument("--target-dir", help="Installation target folder")
    p_in_uninst.add_argument("--profile-dir", help="Profile folder")
    p_in_uninst.add_argument("--purge-data", action="store_true", help="Purge profile data")
    p_in_uninst.set_defaults(func=cmd_installer_uninstall)

    # status
    p_stat = subparsers.add_parser("status", help="Show system and profile status")
    p_stat.add_argument("--profile-dir", help="Custom profile directory")
    p_stat.add_argument("--catalog-path", help="Custom catalog sqlite path")
    p_stat.set_defaults(func=cmd_status)

    # service
    p_srv = subparsers.add_parser("service", help="Run MCP stdio transport service")
    p_srv.add_argument("--catalog-path", help="Path to catalog database")
    p_srv.add_argument("--workspace-id", help="Workspace UUID")
    p_srv.add_argument("--principal-id", help="Principal identity")
    p_srv.add_argument("--refresh-policy", default="manual_only")
    p_srv.add_argument("--scheduled-refresh-root", help="Root ID for interval scan")
    p_srv.add_argument("--poll-interval-sec", type=float, default=2.0)
    p_srv.add_argument("--shutdown-timeout-sec", type=float, default=2.0)
    p_srv.add_argument("--can-trigger-refresh", action="store_true")
    p_srv.add_argument("--can-approve-tasks", action="store_true",
                       help="Expose approve_task to this connection (trusted host decision)")
    p_srv.add_argument("--can-review-tasks", action="store_true",
                       help="Expose review_task_result to this connection (trusted host decision)")
    p_srv.add_argument("--stale-ttl-sec", type=float, default=0.0)
    p_srv.set_defaults(func=cmd_service)

    # task (human operator)
    p_task = subparsers.add_parser("task", help="Inspect, approve and review harness tasks (operator)")
    task_sub = p_task.add_subparsers(dest="task_cmd", required=True)

    def _task_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--profile-dir", help="Custom profile directory")
        p.add_argument("--workspace-id")
        p.add_argument("--principal-id")
        p.set_defaults(func=cmd_task)

    p_t_list = task_sub.add_parser("list")
    _task_common(p_t_list)
    p_t_list.add_argument("--state", action="append")
    p_t_list.add_argument("--limit", type=int, default=20)
    for name in ("show", "approve", "revoke"):
        p_t = task_sub.add_parser(name)
        _task_common(p_t)
        p_t.add_argument("task_id")
    p_t_events = task_sub.add_parser("events")
    _task_common(p_t_events)
    p_t_events.add_argument("task_id")
    p_t_events.add_argument("--after-seq", type=int, default=0)
    p_t_events.add_argument("--limit", type=int, default=100)
    p_t_cancel = task_sub.add_parser("cancel")
    _task_common(p_t_cancel)
    p_t_cancel.add_argument("task_id")
    p_t_cancel.add_argument("--reason")
    p_t_review = task_sub.add_parser("review")
    _task_common(p_t_review)
    p_t_review.add_argument("task_id")
    p_t_review.add_argument("--decision", required=True, choices=["accept", "reject", "rework"])
    p_t_review.add_argument("--step-id")
    p_t_review.add_argument("--note")
    p_t_purge = task_sub.add_parser("purge-expired")
    _task_common(p_t_purge)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    from pdx_local_ai.windows_runtime_terms import require_acceptance
    try:
        # Installation enforces explicit acceptance in Installer.install before
        # touching the target. Uninstall is always available for safe cleanup.
        if args.command not in {'terms', 'installer'}:
            require_acceptance()
        return args.func(args)
    except (OSError, ValueError, KeyError) as exc:
        sys.stderr.write(f'[ERROR] {exc}\n')
        return 1


if __name__ == "__main__":
    sys.exit(main())
