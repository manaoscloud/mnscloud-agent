param(
  [string]$ApiBase = $env:MNSCLOUD_API_BASE,
  [string]$Name = $env:AGENT_NAME,
  [string]$Ref = $env:MNSCLOUD_AGENT_REF
)

$ErrorActionPreference = "Stop"
$RepoDir = Split-Path -Parent $PSScriptRoot

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  throw "Run this updater from an elevated PowerShell session."
}

if (-not $Ref) {
  throw "-Ref is required. Production Agent updates must use a release tag/ref."
}

if (Test-Path (Join-Path $RepoDir ".git")) {
  Push-Location $RepoDir
  try {
    git fetch --all --tags --prune
    git -c advice.detachedHead=false checkout $Ref
  } finally {
    Pop-Location
  }
} else {
  throw "Repository metadata not found; cannot check out $Ref."
}

& "$PSScriptRoot\install-agent-windows.ps1" -ApiBase $ApiBase -Name $Name
Restart-Service -Name "MNSCloudAgent" -Force
Get-Service -Name "MNSCloudAgent"
