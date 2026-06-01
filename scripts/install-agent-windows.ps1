param(
  [string]$ApiBase = $env:MNSCLOUD_API_BASE,
  [string]$EnrollmentToken = $env:MNSCLOUD_AGENT_ENROLLMENT_TOKEN,
  [string]$InstallLabel = $env:MNSCLOUD_AGENT_INSTALL_LABEL,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$ServiceName = "MNSCloudAgent"
$InstallDir = "C:\Program Files\MNSCloud\Agent"
$ConfigDir = Join-Path $env:ProgramData "MNSCloud\Agent"
$ConfigFile = Join-Path $ConfigDir "agent.conf"
$UuidFile = Join-Path $ConfigDir "agent.uuid"
$TokenFile = Join-Path $ConfigDir "agent.token"
$RunScript = Join-Path $InstallDir "run-agent.ps1"
$DefaultApiBase = if ($ApiBase) { $ApiBase.TrimEnd("/") } else { "https://api.publichost.cloud" }
$AgentInstallLabel = if ($InstallLabel) { $InstallLabel } else { $env:COMPUTERNAME }

function Write-Step([string]$Message) {
  Write-Host "[install-agent-windows] $Message"
}

function Get-AgentVersion {
  $versionPath = Join-Path $PSScriptRoot "..\VERSION"
  if (Test-Path $versionPath) {
    return (Get-Content $versionPath -Raw).Trim()
  }
  return "1.0.0"
}

function Get-AgentBuildRef {
  try {
    $ref = git -C (Join-Path $PSScriptRoot "..") rev-parse --short=12 HEAD 2>$null
    if ($ref) { return $ref.Trim() }
  } catch {}
  return "unknown"
}

function Write-AgentBuildMetadata {
  $version = Get-AgentVersion
  $buildRef = Get-AgentBuildRef
  $buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  Invoke-Step {
    Set-Content -Path (Join-Path $InstallDir "VERSION") -Value $version -Encoding ASCII
    @{
      version = $version
      buildRef = $buildRef
      buildDate = $buildDate
      updateChannel = "stable"
      sourceRepo = "manaoscloud/mnscloud-agent"
    } | ConvertTo-Json | Set-Content -Path (Join-Path $InstallDir "build.json") -Encoding UTF8
  }
}

function Invoke-Step([scriptblock]$Block) {
  if ($DryRun) {
    Write-Step "DRY-RUN: $Block"
    return
  }
  & $Block
}

function Ensure-Deno {
  $deno = Get-Command deno -ErrorAction SilentlyContinue
  if ($deno) {
    Write-Step "Deno is available: $($deno.Source)"
    return $deno.Source
  }

  Write-Step "Installing Deno for Windows"
  Invoke-Step { irm https://deno.land/install.ps1 | iex }
  $candidate = Join-Path $env:USERPROFILE ".deno\bin\deno.exe"
  if (!(Test-Path $candidate)) {
    throw "Deno installation did not create $candidate"
  }
  return $candidate
}

function Write-AgentConfig([string]$DenoPath) {
  $content = @"
# MNSCloud Agent configuration
# Managed by scripts/install-agent-windows.ps1

[agent]
name = $AgentInstallLabel
hostname = $env:COMPUTERNAME
api_base = $DefaultApiBase
poll_interval_ms = 15000
heartbeat_interval_ms = 60000
cyber_security_sync_interval_ms = 60000

[identity]
agent_uuid_file = $UuidFile
agent_token_file = $TokenFile

[recordings]
roots = $($env:ProgramData)\MNSCloud\Recordings
mounts =
delete_after_upload = true

[media_files]
roots = $($env:ProgramData)\MNSCloud\MediaFiles
mounts =

[capabilities]
windows.status = true
windows.package.install = true
windows.service.manage = true
windows.file.manage = true
windows.eventlog.read = true
windows.firewall.manage = true
windows.defender.status = true
security.crowdsec.manage = true
security.windows.firewall.manage = true
security.windows.eventlog.read = true
security.windows.defender.manage = false
shell.exec = false

[commands]
timeout_ms = 15000
"@
  Invoke-Step { Set-Content -Path $ConfigFile -Value $content -Encoding UTF8 }
}

function Enroll-Agent {
  if (-not $EnrollmentToken) {
    if (Test-Path $TokenFile) {
      Write-Step "Existing agent token found at $TokenFile"
      return
    }
    throw "Provide -EnrollmentToken or MNSCLOUD_AGENT_ENROLLMENT_TOKEN to enroll this agent."
  }

  $uuid = (Get-Content $UuidFile -Raw).Trim()
  $endpoint = "$DefaultApiBase/api/v1/agent/enroll"
  $payload = @{
    enrollmentToken = $EnrollmentToken
    agentUUID = $uuid
    installationName = $AgentInstallLabel
    hostname = $env:COMPUTERNAME
  } | ConvertTo-Json -Depth 5

  Write-Step "Enrolling agent through $endpoint"
  if ($DryRun) {
    Write-Step "DRY-RUN: enrollment request skipped"
    return
  }

  $response = Invoke-RestMethod -Method Post -Uri $endpoint -ContentType "application/json" -Body $payload
  $runtimeToken = $response.data.agentToken
  $activatedUuid = $response.data.agentUUID
  if (-not $runtimeToken) {
    throw "Enrollment response did not include an agent runtime token."
  }

  if ($activatedUuid) {
    Set-Content -Path $UuidFile -Value $activatedUuid -Encoding ASCII -NoNewline
  }
  Set-Content -Path $TokenFile -Value $runtimeToken -Encoding ASCII -NoNewline
}

function Test-AgentIdentity {
  if ($EnrollmentToken) {
    return
  }
  if ($DryRun) {
    Write-Step "DRY-RUN: identity validation request skipped"
    return
  }
  if (!(Test-Path $UuidFile) -or !(Test-Path $TokenFile)) {
    throw "Existing Agent UUID/token not found. Generate a new install command from MNSCloud and pass -EnrollmentToken."
  }

  $uuid = (Get-Content $UuidFile -Raw).Trim()
  $runtimeToken = (Get-Content $TokenFile -Raw).Trim()
  $endpoint = "$DefaultApiBase/api/v1/agent/heartbeat"
  $payload = @{
    hostname = $env:COMPUTERNAME
    version = Get-AgentVersion
    buildRef = Get-AgentBuildRef
    updateChannel = "stable"
    installerValidation = $true
  } | ConvertTo-Json -Depth 5

  Write-Step "Validating existing Agent identity with MNSCloud API."
  try {
    Invoke-RestMethod `
      -Method Post `
      -Uri $endpoint `
      -ContentType "application/json" `
      -Headers @{
        "X-MNSCloud-Agent-UUID" = $uuid
        "Authorization" = "Bearer $runtimeToken"
      } `
      -Body $payload | Out-Null
  } catch {
    throw "Existing Agent identity is not valid in MNSCloud. Run scripts\uninstall-agent-windows.ps1 and generate a new install command."
  }
}

function Install-Service([string]$DenoPath) {
  $runContent = @"
`$env:MNSCLOUD_AGENT_CONFIG = "$ConfigFile"
& "$DenoPath" run --allow-read --allow-write --allow-net --allow-run --allow-env "$InstallDir\main.ts"
"@
  Invoke-Step { Set-Content -Path $RunScript -Value $runContent -Encoding UTF8 }

  $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($existing) {
    Write-Step "Stopping existing service"
    Invoke-Step { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue }
    Invoke-Step { sc.exe delete $ServiceName | Out-Null }
    Start-Sleep -Seconds 2
  }

  $binPath = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$RunScript`""
  Write-Step "Creating Windows service $ServiceName"
  Invoke-Step { sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= "MNSCloud Agent" | Out-Null }
  Invoke-Step { sc.exe description $ServiceName "MNSCloud native agent" | Out-Null }
  Invoke-Step { Start-Service -Name $ServiceName }
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  throw "Run this installer from an elevated PowerShell session."
}

if (-not $EnrollmentToken) {
  Test-AgentIdentity
}

Write-Step "Preparing directories"
Invoke-Step {
  New-Item -ItemType Directory -Force -Path $InstallDir, $ConfigDir, "$($env:ProgramData)\MNSCloud\Recordings", "$($env:ProgramData)\MNSCloud\MediaFiles" | Out-Null
}

$DenoSource = Ensure-Deno
$DenoPath = Join-Path $InstallDir "deno.exe"
Write-Step "Copying agent runtime"
Invoke-Step {
  Copy-Item -Path $DenoSource -Destination $DenoPath -Force
  Copy-Item -Path "$PSScriptRoot\..\main.ts" -Destination "$InstallDir\main.ts" -Force
  Copy-Item -Path "$PSScriptRoot\..\deno.jsonc" -Destination "$InstallDir\deno.jsonc" -Force
}
Write-AgentBuildMetadata

if (!(Test-Path $UuidFile)) {
  Write-Step "Creating agent UUID"
  Invoke-Step { Set-Content -Path $UuidFile -Value ([guid]::NewGuid().ToString()) -Encoding ASCII }
}

Write-AgentConfig -DenoPath $DenoPath
Enroll-Agent
Test-AgentIdentity
Install-Service -DenoPath $DenoPath

$uuid = if (Test-Path $UuidFile) { (Get-Content $UuidFile -Raw).Trim() } else { "<dry-run>" }
Write-Step "mnscloud-agent installed as Windows service."
Write-Step "Agent UUID: $uuid"
if ($EnrollmentToken) {
  Write-Step "Agent enrolled and service started."
} else {
  Write-Step "Existing Agent identity validated and service started."
}
