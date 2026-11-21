# Agent onboarding

This version is a Windows local, single-user core. Every agent connects to the same stdio MCP entry: `pdx-local service`.

Not in this version: a multi-user website HTTP API, sign-in, web review, and Linux cloud deployment. Those are the next stage. This guide does not restate measurement numbers.

## 1. Local setup

The per-user installer places the executable at
`%LOCALAPPDATA%\Programs\ProDocuX\LocalAI\pdx-local.exe` by default. If you
used `install.ps1 -TargetDir`, use `pdx-local.exe` from that directory.

Installing with `install.ps1 -AcceptWindowsRuntimeTerms` records acceptance.
For a portable copy, review the displayed terms and accept them before `init`.
Run these commands from the directory containing the extracted executable.

```powershell
.\pdx-local.exe terms show
.\pdx-local.exe terms accept --accept-windows-runtime-terms --terms-sha256 '<displayed SHA-256>'
```

The default principal is `default-user`. The examples use `local-user` as a
custom principal. If you choose one, use the same `--principal-id` with
`init`, `source add`, and config preview or service startup.

1. After install, run `pdx-local init`. Add `--profile-dir`, `--workspace-id`, and `--principal-id` when the defaults are not the ones you want.
2. `pdx-local source add <directory> --principal-id <principal>`. A new source denies read by default; add `--inherit-read` only when you intend to grant it. Note the root id from `source list`, then run `pdx-local source scan <root_id>`. Without that scan, files are not in the index yet.
3. Check the entry with the `service` arguments below. Do not add approval flags to this command. When `--refresh-policy` is omitted, the default is `manual_only`, which is why the scan in the previous step is required.

```text
pdx-local service --catalog-path <catalog.sqlite> --workspace-id <workspace uuid> --principal-id <principal>
```

Before `pdx-local agent config cursor` or `pdx-local agent config preview`, the catalog needs at least one enabled source root, or the command needs `--scheduled-root-id`. If both are missing, the command prints an error and exits. It does not emit a config that simply omits the background scan. When a root is present or `--scheduled-root-id` is passed, the preview adds `--refresh-policy interval_scan` and `--scheduled-refresh-root`. Tasks do not depend on those arguments.

## 2. Client config

`--apply` writes only Cursor's `mcp.json`. Other clients paste the preview themselves.

```text
pdx-local agent config preview --client cursor
pdx-local agent config preview --client claude-desktop
pdx-local agent config preview --client claude-code
pdx-local agent config preview --client codex
pdx-local agent config preview --client antigravity
```

The first preview argument is `service`. Generate the config from the installed `pdx-local.exe`, or pass `--binary-path <path to pdx-local.exe>`. Running it from a virtual environment without `--binary-path` sets `command` to that environment's `python.exe` followed by `service`, and the agent cannot start from that config.

| Client | Config location | Snippet |
|---|---|---|
| Cursor | `%USERPROFILE%\.cursor\mcp.json` | `mcpServers.pdx-local-ai` |
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` | Same object |
| Claude Code | Project `.mcp.json` | Same object. `claude mcp add --transport stdio` can take the same `service` arguments |
| Codex | `%USERPROFILE%\.codex\config.toml` | `[mcp_servers.pdx-local-ai]`, with `command` and `args` |
| Antigravity | `%USERPROFILE%\.gemini\config\mcp_config.json`, or MCP Servers → Manage MCP Servers → View raw config | JSON `mcpServers.pdx-local-ai` entry. |

See the [Antigravity IDE MCP instructions](https://antigravity.google/docs/ide-mcp)
for the configuration menu.

Use the paths and IDs from your preview. These examples use sample paths and
the default `manual_only` refresh behavior. To retain interval scans, copy all
arguments from your generated preview.

For Cursor, Claude Desktop, Claude Code project config, and Antigravity,
merge this JSON entry into the existing `mcpServers` object.

```json
{
  "mcpServers": {
    "pdx-local-ai": {
      "command": "C:/Example/LocalAI/pdx-local.exe",
      "args": [
        "service", "--catalog-path", "C:/Example/Profile/catalog.sqlite",
        "--workspace-id", "00000000-0000-4000-8000-000000000001",
        "--principal-id", "local-user"
      ]
    }
  }
}
```

For Codex, add this TOML table to `config.toml`.

```toml
[mcp_servers.pdx-local-ai]
command = "C:/Example/LocalAI/pdx-local.exe"
args = [
  "service", "--catalog-path", "C:/Example/Profile/catalog.sqlite",
  "--workspace-id", "00000000-0000-4000-8000-000000000001",
  "--principal-id", "local-user"
]
```

Claude Code also accepts a project-scoped entry from PowerShell.

```powershell
claude mcp add --transport stdio --scope project pdx-local-ai -- 'C:/Example/LocalAI/pdx-local.exe' service --catalog-path 'C:/Example/Profile/catalog.sqlite' --workspace-id '00000000-0000-4000-8000-000000000001' --principal-id 'local-user'
```

Do not put approval tools on the MCP connection. A person adds `--can-approve-tasks` or `--can-review-tasks` in a terminal only when that grant is intended. Leave them off by default.

## 3. Verify the connection

Reload the client and confirm it lists the `pdx-local-ai` server and the
`search_documents` tool. Ask the agent to search for a distinctive phrase in
a readable, scanned document. Pass the registered root ID in `source_root_ids`
and the phrase in `query`. A successful response has `status: completed`, a
`receipt_id`, and a matching result containing document text and a citation.
If the server connects but returns no matching text, check the configured
catalog, workspace and principal, then verify the source was scanned and is
readable by that principal.

`UNAUTHORIZED_REFRESH_SKIPPED` indicates that the request did not have
permission to refresh the index. A completed search can still return results
from the existing index. Run `source scan` in a terminal to refresh it.

## 4. Human approval in a terminal

An agent cannot approve its own task. The same Windows user runs:

```text
pdx-local task list --profile-dir <profile>
pdx-local task show <task_id> --profile-dir <profile>
pdx-local task approve <task_id> --profile-dir <profile>
pdx-local task review <task_id> --decision accept|reject|rework --step-id <step> --note "..."
pdx-local task cancel <task_id> --reason "..."
```

## 5. Rules to paste to the agent

> Call `list_task_templates`, then `create_task`. Tell me the task id and stop until I run `pdx-local task approve` in a terminal. Do not continue before that approval. After approval, call `get_task_context`. Use a new `idempotency_key` for each `dispatch_task_action`; reuse the same key only to retry. Then `submit_task_result` for the step. Follow `envelope.next` and `envelope.available_actions`. Do not fill in a value that is not in the evidence.
>
> Do not paste a published note into the question. The question only asks the question. Inside a `doc_memory_artifact` task, you call the `recall_published_memory` action through `dispatch_task_action`, then answer from that action's result.
>
> After a multihop search, read the packet JSON returned by `get_task_context`. Do not switch to the hop-chain text. Use the plain-text windows only when that JSON was not sent.
>
> Start the completion length at 4096. Do not set 64. If a model fills 4096 and the finish reason is still length, raise that model's ceiling.
