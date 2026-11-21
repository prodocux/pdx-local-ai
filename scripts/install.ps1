<#
.SYNOPSIS
    ProDocuX Local AI Windows Native Installer Shell
.DESCRIPTION
    Installs, upgrades, or reinstalls pdx-local to user program folder.
    Zero Python dependency. Uses bundled binary distribution with maintenance locking,
    session termination, online SQLite backup, and staged directory swap.
#>
[CmdletBinding()]
param(
    [string]$TargetDir = "$env:LOCALAPPDATA\Programs\ProDocuX\LocalAI",
    [string]$ProfileDir = "$env:LOCALAPPDATA\ProDocuX\LocalAI\profiles\default",
    [string]$Version = "0.0.1",
    [switch]$AcceptWindowsRuntimeTerms
)

$ErrorActionPreference = "Stop"

if (-not $AcceptWindowsRuntimeTerms) {
    Write-Error 'Read WINDOWS-RUNTIME-TERMS.txt and THIRD-PARTY-NOTICES.txt, then explicitly pass -AcceptWindowsRuntimeTerms. Nothing installed.'
    exit 1
}

# Locate bundled binary in package (no host Python required!)
$binDir = Join-Path $PSScriptRoot "bin"
$binExe = Join-Path $binDir "pdx-local.exe"

if (-not (Test-Path $binExe)) {
    Write-Error "[pdx-install] Could not find pdx-local.exe at '$binExe'. The installation package may be incomplete or incorrectly extracted."
    exit 1
}

Write-Host "[pdx-install] Starting ProDocuX Local AI Windows Installation (v$Version)..."
Write-Host "[pdx-install] Source: $binDir"
Write-Host "[pdx-install] Target: $TargetDir"
Write-Host "[pdx-install] Profile: $ProfileDir"

& "$binExe" installer install --source-dist "$binDir" --target-dir "$TargetDir" --profile-dir "$ProfileDir" --version "$Version" --accept-windows-runtime-terms
if ($LASTEXITCODE -ne 0) {
    Write-Error "[pdx-install] Installation failed with exit code $LASTEXITCODE."
    exit $LASTEXITCODE
}

# Copy uninstall.ps1 into TargetDir for convenient uninstallation
$uninstallSrc = Join-Path $PSScriptRoot "uninstall.ps1"
if (Test-Path $uninstallSrc) {
    Copy-Item -Path $uninstallSrc -Destination (Join-Path $TargetDir "uninstall.ps1") -Force -ErrorAction SilentlyContinue
}

Write-Host "[pdx-install] Done. Run '$TargetDir\pdx-local.exe --help' to verify."
