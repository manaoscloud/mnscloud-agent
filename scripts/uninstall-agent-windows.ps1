param(
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$ServiceName = "MNSCloudAgent"
$InstallDir = "C:\Program Files\MNSCloud\Agent"
$ConfigDir = Join-Path $env:ProgramData "MNSCloud\Agent"

function Write-Step([string]$Message) {
  Write-Host "[uninstall-agent-windows] $Message"
}

function Invoke-Step([scriptblock]$Block) {
  if ($DryRun) {
    Write-Step "DRY-RUN: $Block"
    return
  }
  & $Block
}

function Remove-PathIfExists([string]$Path) {
  if (Test-Path -LiteralPath $Path) {
    Write-Step "Removing $Path"
    Invoke-Step { Remove-Item -LiteralPath $Path -Recurse -Force }
  } else {
    Write-Step "Path already absent: $Path"
  }
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  throw "Run this uninstaller from an elevated PowerShell session."
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  Write-Step "Stopping Windows service $ServiceName"
  Invoke-Step { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue }
  Write-Step "Deleting Windows service $ServiceName"
  Invoke-Step { sc.exe delete $ServiceName | Out-Null }
  if (-not $DryRun) {
    Start-Sleep -Seconds 2
  }
} else {
  Write-Step "Windows service already absent: $ServiceName"
}

Remove-PathIfExists -Path $InstallDir
Remove-PathIfExists -Path $ConfigDir

Write-Step "mnscloud-agent local uninstall completed."
Write-Step "Delete or deactivate the Agent record in MNSCloud before reusing the host identity."
