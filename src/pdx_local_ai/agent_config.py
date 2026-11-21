"""Agent Configuration Generator and Merging Engine for ProDocuX Local AI.

Key Contracts:
1. Preview to stdout by default; instructions and logs to stderr.
2. Modification ONLY when user specifies --apply.
3. Target config merge:
   - Preserves all other MCP servers.
   - Fixed configuration key: 'pdx-local-ai'.
   - Staging in temp file + atomic os.replace.
   - Pre-merge backup with verification.
   - Collision rejection if key exists and points to different command without --force.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


MCP_SERVER_KEY = "pdx-local-ai"
MCP_CLIENTS = ("cursor", "claude-desktop", "claude-code", "codex", "antigravity")


def generate_agent_mcp_config(
    *,
    binary_path: str,
    catalog_path: str,
    workspace_id: str,
    principal_id: str,
    scheduled_root_id: str,
    poll_interval_sec: float = 2.0,
    allow_agent_refresh: bool = False,
) -> dict[str, Any]:
    """Generate the stdio MCP server entry. The first argument is the service command."""
    args = [
        "service",
        "--catalog-path",
        str(Path(catalog_path).resolve()),
        "--workspace-id",
        workspace_id,
        "--principal-id",
        principal_id,
        "--refresh-policy",
        "interval_scan",
        "--poll-interval-sec",
        str(poll_interval_sec),
        "--scheduled-refresh-root",
        scheduled_root_id,
        "--shutdown-timeout-sec",
        "2.0",
    ]
    if allow_agent_refresh:
        args.insert(args.index("--refresh-policy"), "--can-trigger-refresh")

    return {
        "command": str(Path(binary_path).resolve()),
        "args": args,
    }


def _toml_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_mcp_snippet(client: str, server_config: dict[str, Any]) -> str:
    """Render one client's config fragment for the same stdio server."""
    if client not in MCP_CLIENTS:
        raise ValueError(f"unknown MCP client: {client}")
    if client == "codex":
        args = server_config.get("args") or []
        rendered = ",\n  ".join(_toml_string(str(item)) for item in args)
        return (
            "[mcp_servers.pdx-local-ai]\n"
            f"command = {_toml_string(str(server_config.get('command') or ''))}\n"
            f"args = [\n  {rendered}\n]\n"
        )
    body = {"mcpServers": {MCP_SERVER_KEY: server_config}}
    return json.dumps(body, indent=2, ensure_ascii=False) + "\n"


def merge_cursor_mcp_config(
    target_path: Path,
    server_key: str,
    server_config: dict[str, Any],
    *,
    force: bool = False,
) -> tuple[bool, str]:
    """Merge server configuration into target Cursor mcp.json safely."""
    target_path = target_path.resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    existing_data: dict[str, Any] = {"mcpServers": {}}
    initial_hash = None

    if target_path.exists():
        raw_text = target_path.read_text(encoding="utf-8")
        initial_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        try:
            existing_data = json.loads(raw_text)
            if not isinstance(existing_data, dict):
                return False, f"Target {target_path} is not a valid JSON object."
        except json.JSONDecodeError as exc:
            return False, f"Failed to parse existing JSON in {target_path}: {exc}"

    mcp_servers = existing_data.setdefault("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        return False, f"'mcpServers' in {target_path} must be a dictionary."

    if server_key in mcp_servers and not force:
        cur_cmd = mcp_servers[server_key].get("command")
        new_cmd = server_config.get("command")
        if cur_cmd != new_cmd:
            return (
                False,
                f"Conflict: '{server_key}' already exists pointing to '{cur_cmd}'. Use --force to overwrite.",
            )

    # Backup original before modifying
    if target_path.exists():
        backup_path = target_path.with_name(f"{target_path.name}.bak.{int(time.time())}")
        shutil.copy2(target_path, backup_path)

    mcp_servers[server_key] = server_config
    new_text = json.dumps(existing_data, indent=2, ensure_ascii=False) + "\n"

    # Stage in same directory to allow atomic replacement
    temp_file = target_path.with_name(f"{target_path.name}.tmp.{os.getpid()}")
    try:
        temp_file.write_text(new_text, encoding="utf-8")
        # Final pre-replacement conflict check: ensure original file was not mutated in-flight
        if target_path.exists() and initial_hash:
            cur_raw = target_path.read_text(encoding="utf-8")
            cur_hash = hashlib.sha256(cur_raw.encode("utf-8")).hexdigest()
            if cur_hash != initial_hash:
                temp_file.unlink(missing_ok=True)
                return False, "Target file was concurrently modified by another process. Aborted."

        os.replace(temp_file, target_path)
    except Exception as exc:
        temp_file.unlink(missing_ok=True)
        return False, f"Failed to atomic replace {target_path}: {exc}"

    return True, f"Successfully merged '{server_key}' into {target_path}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pdx-local agent config",
        description="Generate and preview / apply Cursor MCP client configuration.",
    )
    parser.add_argument("--binary-path", required=True, help="Path to pdx-local executable")
    parser.add_argument("--catalog-path", required=True, help="Path to catalog sqlite database")
    parser.add_argument("--workspace-id", required=True, help="Workspace UUID")
    parser.add_argument("--principal-id", required=True, help="Principal identity")
    parser.add_argument("--scheduled-root-id", required=True, help="Root ID for background interval scan")
    parser.add_argument("--poll-interval-sec", type=float, default=2.0, help="Interval scan period in seconds")
    parser.add_argument("--allow-agent-refresh", action="store_true", help="Grant agent permission to trigger manual refresh")
    parser.add_argument("--apply", action="store_true", help="Explicitly write / merge into Cursor mcp.json")
    parser.add_argument("--target-mcp-json", help="Custom path to target mcp.json (default ~/.cursor/mcp.json)")
    parser.add_argument("--force", action="store_true", help="Force overwrite existing conflicting server configuration")

    args = parser.parse_args(argv)

    server_cfg = generate_agent_mcp_config(
        binary_path=args.binary_path,
        catalog_path=args.catalog_path,
        workspace_id=args.workspace_id,
        principal_id=args.principal_id,
        scheduled_root_id=args.scheduled_root_id,
        poll_interval_sec=args.poll_interval_sec,
        allow_agent_refresh=args.allow_agent_refresh,
    )

    full_preview = {
        "mcpServers": {
            MCP_SERVER_KEY: server_cfg,
        }
    }

    if not args.apply:
        # Default: Pure preview output to stdout
        sys.stdout.write(json.dumps(full_preview, indent=2, ensure_ascii=False) + "\n")
        sys.stderr.write(
            "\n[INFO] Configuration preview generated.\n"
            "[INFO] No changes were written to disk. Specify --apply to merge into ~/.cursor/mcp.json.\n"
        )
        return 0

    target = Path(args.target_mcp_json) if args.target_mcp_json else Path.home() / ".cursor" / "mcp.json"
    ok, msg = merge_cursor_mcp_config(target, "pdx-local-ai", server_cfg, force=args.force)
    if not ok:
        sys.stderr.write(f"[ERROR] {msg}\n")
        return 1

    sys.stderr.write(f"[SUCCESS] {msg}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
