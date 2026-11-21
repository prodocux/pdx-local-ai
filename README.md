# PDX Local AI

PDX Local AI gives your AI assistant three capabilities on your Windows PC:
**tasks, documents, and memory**. Connect it over MCP from an assistant such
as Cursor, Claude, Codex, or Antigravity.

- **Tasks.** Run a structured job with human approval, bounded steps, and
  reviewable results. For example, ask your assistant to check a project
  handoff against a checklist. The assistant proposes the task, waits for
  your approval, and submits its findings for verification and review.
- **Documents.** Index folders you select, search their contents, and retrieve
  matching passages with source citations. For example, ask which decision
  was recorded in your meeting notes and follow the citation back to the
  original passage.
- **Memory.** Keep working notes and reuse approved, published memory in later
  tasks. For example, an evidence-backed handoff note can be proposed for
  durable memory. After human approval and publication, a later task can
  recall the note through its memory tool. Proposals stay out of published
  recall until they are published.

PDX Local AI stores its index, task state, and memory locally. Your connected
assistant handles the conversation and may send retrieved content to its model
provider. Choose the folders and content you share with that in mind.

Install the Windows package and follow [Agent onboarding](docs/AGENT_ONBOARDING.md).
See the [task operations guide](docs/TASK_HARNESS_OPERATIONS.md) for approval,
review, and memory workflows.

## Download v0.0.1

[Download PDX Local AI for Windows x64](https://github.com/prodocux/pdx-local-ai/releases/download/v0.0.1/pdx-local-ai-windows-x64-v0.0.1.zip).

Review the bundled runtime terms and third-party notices before accepting them
in the installer or portable EXE.

ZIP SHA-256: `eb206a6fc39d92cb1d487e8c31e27bbcf275bfd85de8bf6eed40ad346acb6954`.

## Release scope

This Windows x64 release runs locally for one Windows user. It covers local
document indexing and search, citations, stdio MCP access, and the local task
and memory workflows described in [Agent onboarding](docs/AGENT_ONBOARDING.md).
Linux and macOS deployments, hosted HTTP access, and multi-tenant web hosting
are outside the supported scope of this delivery.

Workspace-level canonical knowledge (L3), semantic retrieval escalation,
document expansion and reranking, and long-text continuation are outside this
release's supported feature set. Runtime modules, schemas, and policy files
may be present for compatibility or staged development.
The Farpals adapter is present in the source, but the local MCP service does
not enable it. The release supports the standalone workflow.

## Windows bundled runtime terms

Windows delivery keeps its runtime DLLs local to the application. Before
installing, read `WINDOWS-RUNTIME-TERMS.txt` and `THIRD-PARTY-NOTICES.txt`, then
explicitly pass `-AcceptWindowsRuntimeTerms` to `install.ps1`. Direct installer
CLI usage requires `--accept-windows-runtime-terms` as well. Portable Windows
usage requires `pdx-local terms show`, followed by `pdx-local terms accept
--accept-windows-runtime-terms --terms-sha256 <displayed SHA-256>`.
Acceptance is local and bound to the EXE and terms hashes, not transmitted.
The bundled Windows runtime terms preserve the existing product and Python
licenses. See
[Windows runtime maintenance](docs/WINDOWS_RUNTIME_MAINTENANCE.md) for update
responsibility, acceptance limitations and release-owner review requirements.

## Candidate CI

Use Python 3.12.2 x64 for the development/build driver:

```powershell
python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pytest tests/test_validation.py tests/test_public_delivery_ci.py tests/test_windows_runtime_terms.py -v
python -m PyInstaller pdx-local.spec --noconfirm
python scripts/package_distribution.py --batch candidate-example
```

The three-job workflow tests source, builds a new CI candidate, then validates
that exact ZIP by SHA-256. The delivery probe installs to an isolated directory
and calls the installed EXE, not source code. It verifies MCP search content,
citation/receipt, EOF shutdown, and uninstall retaining profile data.
Hosted CI builds and tests a separate package. The published Windows ZIP
passed the clean Windows and runtime distribution reviews for the SHA-256
listed above.

The delivery gate uses the source tests above, the compiled runtime checks,
the installed-EXE probe, and the package acceptance suite against the exact
ZIP hash. Package-dependent tests require the candidate binary and its ZIP.
Historical Gate 4B-2 through 5A-2 approval, hash-lock, and activation tests
run in the private development root. They depend on historical records or
fixtures and are outside this public delivery gate. The export keeps their
review records and evidence-dependent test modules in the development root.

## Local package use

Extract a reviewed package, review the bundled terms/notices, and run
`install.ps1 -AcceptWindowsRuntimeTerms`. The default installation is
per-user; document sources and profiles remain separate. Initialize with
`pdx-local init`, add a source root, then connect an agent through
[Agent onboarding](docs/AGENT_ONBOARDING.md). New sources default to deny;
`--inherit-read` is explicit. `pdx-local agent config cursor --apply`
can write Cursor's mcp.json; `pdx-local agent config preview` prints the same
`service` entry for Claude, Codex, and Antigravity. `--apply` writes only Cursor.
Uninstall retains profile data by default. Never run purge without reviewing
its source-directory overlap checks.

## Public export

Only public-export.allowlist entries are eligible. scripts/export_public_root.py
first audits the complete list, rejects private state and reparse points, then
optionally copies to a NEW independent root and checks every file byte-for-byte.
The export contains source and documentation. Keep raw build and test logs
outside the public root and release assets.
Commit, push, freeze, and release each require explicit authority.

See [export manifest](docs/PUBLIC_EXPORT_MANIFEST.md),
[export policy](docs/PUBLIC_EXPORT_POLICY.md),
[architecture](docs/ARCHITECTURE.md), [data model](docs/DATA_MODEL.md),
and [Windows security](docs/SECURITY_WINDOWS.md).
