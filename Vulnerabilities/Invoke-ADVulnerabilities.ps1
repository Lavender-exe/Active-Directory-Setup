<#
.SYNOPSIS
  Introduce (or undo) common, intentional AD misconfigurations for a defensive lab.

.DESCRIPTION
  Reads a vulnerabilities spec (see config\vulns.example.json) and applies the
  enabled misconfigurations to the domain so defenders can practise finding,
  detecting and remediating real attack paths (Kerberoasting, AS-REP roasting,
  delegation abuse, dangerous ACLs, DCSync, credential exposure, dangerous group
  membership, ADCS ESC1).

  Every change is reversible: re-run with -Undo to reset the lab. Each module
  also prints a [blue-team] detection/remediation note. Run on the DC (or a box
  with RSAT-AD-Tools) in an elevated session.

  !!  LAB USE ONLY. These scripts deliberately weaken Active Directory. Never run
  !!  them against a production or internet-reachable domain.

.PARAMETER Config
  Path to the vulnerabilities spec JSON.

.PARAMETER Only
  Apply/undo just one vulnerability by its config key (runs even if disabled).

.PARAMETER Undo
  Revert the changes instead of applying them.

.PARAMETER DryRun
  Log what would happen without changing anything (safe on any machine).

.EXAMPLE
  .\Invoke-ADVulnerabilities.ps1 -Config config\vulns.example.json -DryRun
  .\Invoke-ADVulnerabilities.ps1 -Config config\vulns.json
  .\Invoke-ADVulnerabilities.ps1 -Config config\vulns.json -Undo
  .\Invoke-ADVulnerabilities.ps1 -Config config\vulns.json -Only dcsync
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$Config,
  [string]$Only,
  [switch]$Undo,
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$modules = Join-Path $PSScriptRoot 'modules'
. (Join-Path $modules 'Common.ps1')

$Config = (Resolve-Path -LiteralPath $Config).Path
$cfg = Get-VulnConfig -Path $Config

# Ordered registry of vulnerabilities: config key -> module + extra args.
$registry = @(
  @{ Key = 'kerberoasting';           Script = 'Invoke-Kerberoastable.ps1';   Extra = @{} }
  @{ Key = 'asrepRoasting';           Script = 'Invoke-ASREPRoastable.ps1';   Extra = @{} }
  @{ Key = 'unconstrainedDelegation'; Script = 'Invoke-Delegation.ps1';       Extra = @{ DelegationType = 'Unconstrained' } }
  @{ Key = 'constrainedDelegation';   Script = 'Invoke-Delegation.ps1';       Extra = @{ DelegationType = 'Constrained' } }
  @{ Key = 'dangerousAcl';            Script = 'Invoke-DangerousACL.ps1';     Extra = @{} }
  @{ Key = 'dcsync';                  Script = 'Invoke-DCSync.ps1';           Extra = @{} }
  @{ Key = 'credentialExposure';      Script = 'Invoke-CredentialExposure.ps1'; Extra = @{} }
  @{ Key = 'dangerousGroups';         Script = 'Invoke-GroupMembership.ps1';  Extra = @{} }
  @{ Key = 'adcs';                    Script = 'Invoke-ADCSVulns.ps1';        Extra = @{} }
  @{ Key = 'adfs';                    Script = 'Invoke-ADFSVulns.ps1';        Extra = @{} }
  @{ Key = 'adws';                    Script = 'Invoke-ADWSExposure.ps1';     Extra = @{} }
)

function Test-VulnEnabled {
  param($Spec)
  return ($Spec -and $Spec.enabled -eq $true)
}

Write-Step "AD vulnerability lab for '$($cfg.domain)'  (config: $Config)"
if ($DryRun) { Write-Info "DRY-RUN: no changes will be made." }
Write-Warn  "LAB USE ONLY. This deliberately weakens Active Directory."
if ($Undo)  { Write-Info "UNDO mode: reverting misconfigurations." }

if (-not $DryRun) { Import-ADModuleOrThrow }

# Undo reverses creation order so dependents come down before their targets.
$items = if ($Undo) { $registry[($registry.Count - 1)..0] } else { $registry }

$applied = 0
foreach ($item in $items) {
  if ($Only -and $item.Key -ne $Only) { continue }
  $spec = $cfg.vulnerabilities.($item.Key)

  if (-not $Only -and -not (Test-VulnEnabled $spec)) { continue }
  if ($Only -and -not $spec) { Write-Warn "No '$Only' section in config."; break }

  $scriptPath = Join-Path $modules $item.Script
  $splat = @{ Spec = $spec; Domain = $cfg.domain; Undo = $Undo; DryRun = $DryRun } + $item.Extra
  try {
    & $scriptPath @splat
    $applied++
  }
  catch {
    Write-Warn "Vulnerability '$($item.Key)' failed: $($_.Exception.Message)"
  }
}

if ($applied -eq 0) { Write-Warn "Nothing ran. Enable vulnerabilities in the config, or use -Only <key>." }
else {
  $verb = if ($Undo) { 'reverted' } else { 'applied' }
  Write-Good "`nDone. $applied vulnerability group(s) $verb for '$($cfg.domain)'."
  if (-not $Undo) { Write-Info "Reset the lab anytime with: -Undo" }
}
