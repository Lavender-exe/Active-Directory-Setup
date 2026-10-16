<#
.SYNOPSIS
  Shared helpers for the AD lab provisioning scripts.

.DESCRIPTION
  Dot-source this file from the orchestrator (Deploy-ADLab.ps1) and from the
  standalone role scripts (Install-*.ps1). It provides logging, config loading,
  a small JSON state file (so provisioning can resume after a reboot), a
  RunOnce resume helper, and a handful of environment checks.

  Nothing in here changes the host; it is safe to dot-source anywhere.
#>

# --- Logging ----------------------------------------------------------------
# Matches the [*]/[+]/[-] colour style already used across the repo.

function Write-Info { param([Parameter(Mandatory)] [string]$Message) Write-Host -ForegroundColor Yellow "[*] $Message" }
function Write-Good { param([Parameter(Mandatory)] [string]$Message) Write-Host -ForegroundColor Green  "[+] $Message" }
function Write-Warn { param([Parameter(Mandatory)] [string]$Message) Write-Host -ForegroundColor Red    "[-] $Message" }
function Write-Step { param([Parameter(Mandatory)] [string]$Message) Write-Host -ForegroundColor Cyan   "`n==> $Message" }

# --- Dry-run wrapper --------------------------------------------------------
# Every state-changing action goes through this. When $DryRun is set the action
# is logged but not executed, so control flow / dispatch / staging can be
# exercised on a non-server box.

function Invoke-LabAction {
  param(
    [Parameter(Mandatory)] [string]$Description,
    [Parameter(Mandatory)] [scriptblock]$Action,
    [switch]$DryRun
  )

  if ($DryRun) {
    Write-Host -ForegroundColor DarkGray "    [dry-run] would: $Description"
    return
  }

  Write-Info $Description
  & $Action
}

# --- Environment checks -----------------------------------------------------

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($id)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-IsAdmin {
  if (-not (Test-IsAdmin)) {
    throw "This script must be run from an elevated (Administrator) PowerShell session."
  }
}

function Test-IsDomainJoined {
  # Domain-joined (not a workgroup). A promoted DC is also domain-joined.
  return (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain
}

function Test-IsDomainController {
  # DomainRole 4 = backup DC, 5 = primary DC.
  $role = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
  return ($role -eq 4 -or $role -eq 5)
}

# --- Config loading / validation -------------------------------------------

$script:KnownRoleTypes = @('ADCS', 'ADFS', 'RSAT')

function Get-LabConfig {
  <#
    Loads and validates a lab spec JSON file. Returns the parsed object.
    Throws with a clear message on the first problem found.
  #>
  param([Parameter(Mandatory)] [string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Config file not found: $Path"
  }

  try {
    $cfg = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
  }
  catch {
    throw "Config file is not valid JSON ($Path): $($_.Exception.Message)"
  }

  if (-not $cfg.domain)          { throw "Config is missing the 'domain' section." }
  if (-not $cfg.domain.fqdn)     { throw "Config is missing 'domain.fqdn' (e.g. moros.local)." }
  if (-not $cfg.domain.netbios)  { throw "Config is missing 'domain.netbios' (e.g. MOROS)." }
  if (-not $cfg.domain.safeModePassword) { throw "Config is missing 'domain.safeModePassword' (DSRM password)." }

  if (-not $cfg.network)          { throw "Config is missing the 'network' section." }
  if (-not $cfg.network.hostname) { throw "Config is missing 'network.hostname'." }

  foreach ($role in @($cfg.roles)) {
    if (-not $role) { continue }
    if (-not $role.type) { throw "Every entry in 'roles' must have a 'type'." }
    if ($script:KnownRoleTypes -notcontains $role.type) {
      throw "Unknown role type '$($role.type)'. Known types: $($script:KnownRoleTypes -join ', ')."
    }
    if (-not $role.target) {
      # Default placement is the box the orchestrator runs on.
      $role | Add-Member -NotePropertyName target -NotePropertyValue 'local' -Force
    }
  }

  return $cfg
}

# --- State file (resume across reboots) -------------------------------------

function Get-LabStatePath {
  # Staged under C:\Windows\Tasks to match where the repo already drops files.
  if ($env:ADLAB_STATE_PATH) { return $env:ADLAB_STATE_PATH }
  return (Join-Path $env:windir 'Tasks\adlab.state.json')
}

function Get-LabState {
  $path = Get-LabStatePath
  if (Test-Path -LiteralPath $path) {
    try { return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
    catch { Write-Warn "State file was unreadable, starting fresh: $path" }
  }
  # Fresh state.
  return [pscustomobject]@{
    configPath      = $null
    completedStages = @()
  }
}

function Set-LabState {
  param(
    [Parameter(Mandatory)] $State,
    [switch]$DryRun
  )
  if ($DryRun) { return }
  $path = Get-LabStatePath
  $dir = Split-Path -Parent $path
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $State | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $path -Encoding UTF8
}

function Add-CompletedStage {
  param(
    [Parameter(Mandatory)] $State,
    [Parameter(Mandatory)] [string]$Stage,
    [switch]$DryRun
  )
  if ($State.completedStages -notcontains $Stage) {
    $State.completedStages = @($State.completedStages) + $Stage
  }
  Set-LabState -State $State -DryRun:$DryRun
  return $State
}

function Test-StageComplete {
  param(
    [Parameter(Mandatory)] $State,
    [Parameter(Mandatory)] [string]$Stage
  )
  return (@($State.completedStages) -contains $Stage)
}

# --- RunOnce resume ---------------------------------------------------------
# After the DC promotion reboot, re-launch the orchestrator automatically. The
# entry is self-clearing (RunOnce), and a documented manual fallback exists.

function Register-ResumeTask {
  param(
    [Parameter(Mandatory)] [string]$ConfigPath,
    [Parameter(Mandatory)] [string]$OrchestratorPath,
    [switch]$DryRun
  )

  $pwsh = (Get-Process -Id $PID).Path   # the current PowerShell host (powershell.exe / pwsh.exe)
  if (-not $pwsh) { $pwsh = 'powershell.exe' }

  $cmd = "`"$pwsh`" -NoProfile -ExecutionPolicy Bypass -File `"$OrchestratorPath`" -Config `"$ConfigPath`" -Resuming"
  $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'

  Invoke-LabAction -DryRun:$DryRun -Description "register RunOnce resume: $cmd" -Action {
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name 'ADLabResume' -Value $cmd
  }
}
