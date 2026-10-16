<#
.SYNOPSIS
  Config-driven provisioner: build a new forest/DC and install role services.

.DESCRIPTION
  Reads a JSON lab spec (see config\lab.example.json) and runs the provisioning
  stages in order:

    Network  -> hostname + static IP + DNS            (Set-DCNetwork)
    Promote  -> AD DS install + Install-ADDSForest     (Install-DC)   [reboots]
    Roles    -> each role in spec.roles[] (ADCS/ADFS/RSAT)
    Users    -> optional: generate + import AD users    (generate_ad.ps1)

  Stage state is kept in a JSON state file so the run can resume after the
  promotion reboot. A RunOnce entry re-launches this script automatically after
  that reboot; if it does not fire, re-run the same command by hand.

  Each role carries a "target" ("local" or a hostname). "local" roles are
  installed on the box this script runs on (i.e. the DC). A role targeting a
  different host prints a copy-and-run runbook for that member server (join it
  with Workstation\Join-AD.ps1, then run the matching modules\Install-*.ps1).

.PARAMETER Config
  Path to the lab spec JSON.

.PARAMETER Stage
  Run only this stage (Network | Promote | Roles | Users).

.PARAMETER Role
  Install only this single role type (ADCS | ADFS | RSAT) on the local machine,
  then exit. Useful on a member server after joining the domain.

.PARAMETER Resuming
  Set automatically by the RunOnce resume entry; not needed by hand.

.PARAMETER DryRun
  Log every state-changing action without executing it. Safe on any machine.

.EXAMPLE
  .\Deploy-ADLab.ps1 -Config config\lab.example.json
  .\Deploy-ADLab.ps1 -Config config\lab.example.json -DryRun
  .\Deploy-ADLab.ps1 -Config config\lab.example.json -Role ADCS
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$Config,
  [ValidateSet('Network', 'Promote', 'Roles', 'Users')] [string]$Stage,
  [ValidateSet('ADCS', 'ADFS', 'RSAT')] [string]$Role,
  [switch]$Resuming,
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$modules = Join-Path $PSScriptRoot 'modules'
. (Join-Path $modules 'Common.ps1')

# Resolve to a full path now; after a reboot the working directory may differ.
$Config = (Resolve-Path -LiteralPath $Config).Path
$cfg = Get-LabConfig -Path $Config

# ---------------------------------------------------------------------------
# Role dispatch: type -> module function. The extension seam for new roles.
# ---------------------------------------------------------------------------
function Invoke-SingleRole {
  param([Parameter(Mandatory)] $RoleSpec, [switch]$DryRun)

  $target = if ($RoleSpec.target) { $RoleSpec.target } else { 'local' }
  $isLocal = ($target -eq 'local') -or ($target -eq $env:COMPUTERNAME)

  if (-not $isLocal) {
    Write-Step "Role '$($RoleSpec.type)' targets member server '$target'"
    Write-Warn "Run this on '$target' (after joining it to the domain):"
    Write-Host "    1) Join-AD.ps1 -Domain $($cfg.domain.fqdn) -DnsServer $($cfg.network.ipAddress) -User $($cfg.domain.netbios)\Administrator -Password <pw> -Restart"
    Write-Host "    2) copy the 'modules' folder to '$target', then:"
    switch ($RoleSpec.type) {
      'ADCS' { Write-Host "       .\Install-ADCS.ps1 -CaType $($RoleSpec.caType) -CaCommonName '$($RoleSpec.caCommonName)' -ValidityYears $($RoleSpec.validityYears)" }
      'ADFS' { Write-Host "       .\Install-ADFS.ps1 -ServiceFqdn '$($RoleSpec.serviceFqdn)' -ServiceAccount '$($RoleSpec.serviceAccount)' -ServiceAccountPassword <pw>" }
      'RSAT' { Write-Host "       .\Install-RSAT.ps1" }
    }
    return
  }

  # Modules are invoked with & (child scope) so their param blocks cannot
  # clobber the orchestrator's variables (notably $DryRun).
  switch ($RoleSpec.type) {
    'ADCS' {
      $caType = if ($RoleSpec.caType) { $RoleSpec.caType } else { 'EnterpriseRootCA' }
      $years  = if ($RoleSpec.validityYears) { [int]$RoleSpec.validityYears } else { 5 }
      & (Join-Path $modules 'Install-ADCS.ps1') -CaType $caType -CaCommonName $RoleSpec.caCommonName -ValidityYears $years -DryRun:$DryRun
    }
    'ADFS' {
      $display = if ($RoleSpec.displayName) { $RoleSpec.displayName } else { "$($cfg.domain.netbios) ADFS" }
      & (Join-Path $modules 'Install-ADFS.ps1') -ServiceFqdn $RoleSpec.serviceFqdn `
        -DisplayName $display `
        -CertThumbprint $RoleSpec.certThumbprint `
        -ServiceAccount $RoleSpec.serviceAccount `
        -ServiceAccountPassword $RoleSpec.serviceAccountPassword `
        -DryRun:$DryRun
    }
    'RSAT' {
      & (Join-Path $modules 'Install-RSAT.ps1') -DryRun:$DryRun
    }
    default { Write-Warn "No handler for role type '$($RoleSpec.type)'." }
  }
}

# ---------------------------------------------------------------------------
# Stage implementations
# ---------------------------------------------------------------------------
function Invoke-NetworkStage {
  param($State, [switch]$DryRun)
  $n = $cfg.network
  $pl  = if ($n.prefixLength) { [int]$n.prefixLength } else { 24 }
  $dns = if ($n.dnsServer) { $n.dnsServer } else { '127.0.0.1' }
  $r = & (Join-Path $modules 'Set-DCNetwork.ps1') -Hostname $n.hostname -IpAddress $n.ipAddress `
    -PrefixLength $pl -Gateway $n.gateway -DnsServer $dns -DryRun:$DryRun

  if ($r.RebootRequired -and -not $DryRun) {
    Register-ResumeTask -ConfigPath $Config -OrchestratorPath $PSCommandPath -DryRun:$DryRun
    Write-Warn "Rebooting to apply hostname change; provisioning resumes automatically."
    Restart-Computer -Force
    exit 0
  }
  return (Add-CompletedStage -State $State -Stage 'Network' -DryRun:$DryRun)
}

function Invoke-PromoteStage {
  param($State, [switch]$DryRun)

  if (Test-IsDomainController) {
    Write-Good "Already a Domain Controller for '$((Get-CimInstance Win32_ComputerSystem).Domain)'."
    return (Add-CompletedStage -State $State -Stage 'Promote' -DryRun:$DryRun)
  }

  # Register resume BEFORE promotion, because Install-ADDSForest reboots itself.
  Register-ResumeTask -ConfigPath $Config -OrchestratorPath $PSCommandPath -DryRun:$DryRun

  $forest = if ($cfg.domain.forestMode) { $cfg.domain.forestMode } else { 'WinThreshold' }
  $domain = if ($cfg.domain.domainMode) { $cfg.domain.domainMode } else { 'WinThreshold' }
  $null = & (Join-Path $modules 'Install-DC.ps1') -DomainName $cfg.domain.fqdn -NetbiosName $cfg.domain.netbios `
    -SafeModePassword $cfg.domain.safeModePassword -ForestMode $forest -DomainMode $domain -DryRun:$DryRun

  # Only reached in DryRun (a real promotion reboots). Resume handles the rest.
  return (Add-CompletedStage -State $State -Stage 'Promote' -DryRun:$DryRun)
}

function Invoke-RolesStage {
  param($State, [switch]$DryRun)
  Write-Step "Installing roles"
  foreach ($r in @($cfg.roles)) {
    if (-not $r) { continue }
    try { Invoke-SingleRole -RoleSpec $r -DryRun:$DryRun }
    catch { Write-Warn "Role '$($r.type)' failed: $($_.Exception.Message)" }
  }
  return (Add-CompletedStage -State $State -Stage 'Roles' -DryRun:$DryRun)
}

function Invoke-UsersStage {
  param($State, [switch]$DryRun)
  Write-Step "Users"
  if (-not $cfg.users) {
    Write-Info "No 'users' section in config; skipping user generation."
    return (Add-CompletedStage -State $State -Stage 'Users' -DryRun:$DryRun)
  }

  $schema = $cfg.users.schema
  if (-not $schema) { $schema = 'ad-schema.json' }
  if (-not [System.IO.Path]::IsPathRooted($schema)) { $schema = Join-Path $PSScriptRoot $schema }

  if ($cfg.users.generate -and -not (Test-Path -LiteralPath $schema)) {
    $g = $cfg.users.generate
    Invoke-LabAction -DryRun:$DryRun -Description "rand_users.ps1 -> $schema (users=$($g.count) groups=$($g.groups) localAdmins=$($g.localAdmins))" -Action {
      & (Join-Path $PSScriptRoot 'rand_users.ps1') $schema ([int]$g.count) ([int]$g.groups) ([int]$g.localAdmins) -Domain $cfg.domain.fqdn
    }
  }

  Invoke-LabAction -DryRun:$DryRun -Description "generate_ad.ps1 $schema" -Action {
    & (Join-Path $PSScriptRoot 'generate_ad.ps1') $schema
  }
  return (Add-CompletedStage -State $State -Stage 'Users' -DryRun:$DryRun)
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
Write-Step "AD lab provisioning for '$($cfg.domain.fqdn)'  (config: $Config)"
if ($DryRun) { Write-Info "DRY-RUN: no changes will be made." }
if ($Resuming) { Write-Info "Resuming after reboot." }

$state = Get-LabState
$state.configPath = $Config

# Single-role mode: install one role locally and exit (e.g. on a member server).
if ($Role) {
  Write-Info "Single-role mode: installing '$Role' on the local machine."
  $spec = @($cfg.roles) | Where-Object { $_.type -eq $Role } | Select-Object -First 1
  if (-not $spec) { $spec = [pscustomobject]@{ type = $Role; target = 'local' } }
  Invoke-SingleRole -RoleSpec $spec -DryRun:$DryRun
  Write-Good "Done."
  return
}

$allStages = @('Network', 'Promote', 'Roles', 'Users')
$stagesToRun = if ($Stage) { @($Stage) } else { $allStages }

foreach ($s in $allStages) {
  if ($stagesToRun -notcontains $s) { continue }
  if (Test-StageComplete -State $state -Stage $s) {
    Write-Good "Stage '$s' already complete; skipping."
    continue
  }
  switch ($s) {
    'Network' { $state = Invoke-NetworkStage -State $state -DryRun:$DryRun }
    'Promote' { $state = Invoke-PromoteStage -State $state -DryRun:$DryRun }
    'Roles'   { $state = Invoke-RolesStage   -State $state -DryRun:$DryRun }
    'Users'   { $state = Invoke-UsersStage   -State $state -DryRun:$DryRun }
  }
}

Write-Good "Provisioning complete for '$($cfg.domain.fqdn)'."
Write-Info  "Verify: Get-ADForest | certutil -CAInfo | Get-AdfsProperties | Get-Service ADWS"
