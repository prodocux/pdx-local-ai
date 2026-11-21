# Windows bundled runtime delivery and maintenance

The first Windows release retains application-local runtime DLLs. No global
Python or administrator-level VC++ runtime installation is required by design.
Linux/macOS builds do not apply the Windows runtime acceptance gate; their own
native dependencies still require independent provenance, license and platform
verification. This document is not evidence of Linux/macOS readiness.

## Acceptance policy

The active terms version is `2026-10-14.3`. Its authoritative bytes are UTF-8
without BOM, with LF line endings. Packages and acceptance records bind the
actual file SHA-256; no separate hard-coded hash constant is required.

Read `WINDOWS-RUNTIME-TERMS.txt` and `THIRD-PARTY-NOTICES.txt` before installation.
Use `install.ps1 -AcceptWindowsRuntimeTerms` only after reviewing the terms.
Unattended deployment owners must ensure they are authorized to accept them.
No environment variable or default setting silently accepts the terms.

For a portable Windows binary, run `pdx-local terms show`, review the terms,
then run `pdx-local terms accept --accept-windows-runtime-terms --terms-sha256
<displayed SHA-256>`. Operational CLI/MCP startup is blocked until acceptance.
Help, terms display and safe uninstall remain available without acceptance.
The binary necessarily loads its runtime before it can check this policy;
this is not a mechanism preventing DLL loading or user tampering.

The local `windows-runtime-acceptance.json` records UTC acceptance time, method,
terms version/hash, product version and EXE hash. It contains no principal, IP
address or machine identifier and is never uploaded. It is an ordinary local
record, not proof of legal capacity or immutable consent. A different EXE or
terms requires acceptance again. Reinstallation explicitly accepts again;
historical evidence is not rewritten. An invalid existing portable acceptance
record causes refusal; the operator can preserve it separately before removal.

## Runtime update responsibility

Owner: ProDocuX Team. Application-local DLLs do not inherit servicing guarantees
from a separately installed system VC++ Redistributable. Track CPython and its
bundled dependencies, Microsoft runtime advisories, and wheel-native components.
Review dependency/security advisories before each release and at least monthly.
For a critical advisory, target triage within 7 days and a validated corrective
candidate within 30 days; these are internal targets, not a hard SLA. If an
acceptable fix is unavailable, record the risk and block release as appropriate.

For every runtime update: record authoritative download URL/version/hash;
compare the shipped binaries; retain license/notice requirements; rebuild a new
named candidate with a full manifest; run affected installation, MCP and
uninstall checks; repeat clean-environment verification when runtime/loading
dependencies change. Never replace DLLs in a signed-off ZIP or reuse an old
candidate SHA as evidence for a rebuilt binary. Do not blindly download a
floating latest runtime or copy arbitrary system DLLs into the package.

## Release gate and limits

The documented basis is the downstream redistribution route for unchanged
official CPython Windows runtime components, subject to the original licenses
and additional Windows binary conditions shipped in CPython 3.12.2 LICENSE.txt.
That file expressly addresses Windows binary redistribution and downstream
protective terms. Microsoft code remains under its own conditions, not PSF's
license. Python documents private runtime inclusion in application installers:
https://docs.python.org/3.12/using/windows.html#the-embeddable-package

Source/hash checks identify the covered files; they are not license grants.
Before sign-off, record conformity to the documented conditions: original
notices preserved, no misleading Microsoft branding, Windows-only distribution
of the Microsoft component, no prohibited uses, and downstream protective
terms/acceptance. Do not impose a generic requirement to buy Visual Studio,
obtain an individual Microsoft permission, or add indemnity merely because
official Python runtime components are redistributed. Resolve any specific
contradictory term if one is identified. This is an adopted compliance reading,
not an unconditional legal certification. The existing provenance audit is
retained separately; documentation changes do not change its tested candidate.
No freeze, public release or legal certification follows automatically.
