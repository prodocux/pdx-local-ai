# Public export candidate manifest

Status: local preparation, pending review and Git authorization. No commit,
push, freeze, or release is implied for this revision. The earlier private CI
candidate and its evidence remain separate; no public release is approved.

## Exact scope

`public-export.allowlist` is the authoritative inventory of 229 files.
It includes all product Python modules, SQL 001-014, runtime JSON schemas,
lexical-first policy JSON, CLI/service/installer entry points, CI harness,
Windows x64 CPython 3.12 wheel lock, notices and selected public documentation.

Historical proposals, review evidence, Git metadata,
virtual environments, caches, databases, original documents, dist artifacts,
trial logs and tests coupled to private Gate records are excluded. The Gate 4C-3
lexical policy JSON and its packaged copy remain as runtime data.

## Export checks

scripts/export_public_root.py checks every entry, Python syntax, full product
module/runtime inventory, reparse points, private state, selected developer
paths, private-key markers and token patterns. This bounded scan does not
guarantee the absence of all secrets; human review is required before push.

A NEW independent directory is created without Git metadata. All file bytes
and SHA-256 values must match source; extra/missing files fail. This provisional
candidate is bound to working-tree hashes, not an approved commit identity.

## CI flow

1. Source tests: validation plus CI harness/allowlist negative tests and
   Windows runtime acceptance-policy tests.
2. Build: Python 3.12.2 x64, hash-locked wheels, PyInstaller, unique
   ci-run_id-run_attempt candidate, SHA-256 and artifact handoff.
3. Delivery: verify exact ZIP/manifest; install to dedicated directory; use
   INSTALLED EXE for init and MCP search; assert expected content plus citation
   and receipt. Product PATH excludes Python, PYTHONPATH is removed. Bounded
   dual-stream collection, EOF/exit check, uninstall/data-preservation checks.
   Then run all 15 acceptance tests with explicit ZIP/SHA, rejecting skips.
   Before operational EXE tests, verify the compiled terms refusal/acceptance
   paths in an isolated copy. The acceptance runner explicitly consents for
   test fixtures and verifies the tested EXE matches the ZIP. Build-machine
   acceptance records are never distributed in the package.
   Evidence upload uses always(), and uninstall failures are not ignored.

Actions are pinned to full commits. Token permission is contents:read;
checkout does not persist credentials. Jobs have timeouts. No secrets,
self-hosted runner, pull_request_target, remote push or Release creation.
Only synthetic test data is used; review evidence before sharing publicly.

Each workflow run builds and verifies its own candidate.

## Release boundaries

windows-2022 includes development software and does NOT close RG-1. A separate
no-Python/no-repository Windows image with actual MCP search remains required.
RG-2 provenance has an independent audit; this revision adds Windows-only
runtime conditions, local acceptance records and update policy. Public-release
sign-off requires a recorded conditions-compliance review for the documented
official CPython downstream distribution route, not an unsupported assumption
that an additional individual Microsoft permission must be obtained.
Windows x64 local single-user operation is the supported deployment scope.
The README lists the candidate's feature and deployment boundaries.

Further commit/push, clean VM work and freeze/release require user decisions.
