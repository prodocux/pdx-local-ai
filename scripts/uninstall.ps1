<#
.SYNOPSIS
    ProDocuX Local AI Windows Native Uninstaller Shell
.DESCRIPTION
    Safely uninstalls pdx-local without requiring host Python.
    Preserves user profile data and document sources by default.
#>
[CmdletBinding()]
param(
    [string]$TargetDir = "$env:LOCALAPPDATA\Programs\ProDocuX\LocalAI",
    [string]$ProfileDir = "$env:LOCALAPPDATA\ProDocuX\LocalAI\profiles\default",
    [switch]$PurgeData = $false
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $TargetDir)) {
    Write-Host "[pdx-uninstall] Target directory $TargetDir does not exist. Nothing to uninstall."
    exit 0
}

# Find pdx-local.exe: prefer already-installed copy (avoids file-lock on running process),
# fall back to bundled binary in this package.
$targetExe = Join-Path $TargetDir "pdx-local.exe"
$bundledExe = Join-Path $PSScriptRoot "bin\pdx-local.exe"

Write-Host "[pdx-uninstall] Starting ProDocuX Local AI Uninstallation..."

# Copy uninstaller binary to temp staging to avoid Windows file-locking on target pdx-local.exe
$tempDir = Join-Path $env:TEMP "pdx-uninstall-$PID"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
try {
    if (Test-Path $targetExe) {
        Copy-Item -Path "$TargetDir\*" -Destination $tempDir -Recurse -Force
    } elseif (Test-Path $bundledExe) {
        $binDir = Split-Path $bundledExe -Parent
        Copy-Item -Path "$binDir\*" -Destination $tempDir -Recurse -Force
    } else {
        Write-Error "[pdx-uninstall] Neither installed pdx-local.exe nor bundled binary found. Cannot safely uninstall."
        exit 1
    }

    $uninstallerExe = Join-Path $tempDir "pdx-local.exe"
    $purgeArgs = if ($PurgeData) { @("--purge-data") } else { @() }

    & "$uninstallerExe" installer uninstall --target-dir "$TargetDir" --profile-dir "$ProfileDir" @purgeArgs
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Write-Error "[pdx-uninstall] Uninstallation failed with exit code $exitCode."
        exit $exitCode
    }
} finally {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "[pdx-uninstall] Successfully uninstalled."
