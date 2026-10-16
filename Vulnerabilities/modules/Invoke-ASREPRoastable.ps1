<#
.SYNOPSIS
  Make accounts AS-REP roastable (Kerberos pre-authentication disabled).

.DESCRIPTION
  With pre-auth disabled an attacker can request an AS-REP for the user without
  knowing the password and crack the encrypted portion offline. This sets
  DONT_REQ_PREAUTH on the listed users (creating them if missing). Undo clears
  the flag; it never deletes users (they may be real accounts).

  Spec shape:  { "users": [ "jdoe", "asrep-svc" ] }
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] $Spec,
  [string]$Domain,
  [switch]$Undo,
  [switch]$DryRun
)
. (Join-Path $PSScriptRoot 'Common.ps1')
if (-not $DryRun) { Import-ADModuleOrThrow }

Write-Step ("{0} AS-REP roastable users" -f ($(if ($Undo) { 'Reverting' } else { 'Creating' })))

foreach ($name in @($Spec.users)) {
  if (-not $name) { continue }

  if ($Undo) {
    if (-not $DryRun) {
      $u = Get-ADUser -Filter "SamAccountName -eq '$name'" -ErrorAction SilentlyContinue
      if (-not $u) { Write-Warn "User '$name' not found; skipping."; continue }
    }
    Invoke-VulnAction -DryRun:$DryRun -Description "re-enable Kerberos pre-auth for '$name'" -Action {
      Set-ADAccountControl -Identity $name -DoesNotRequirePreAuth $false
    }
    continue
  }

  $null = Resolve-ADUserOrCreate -Name $name -DryRun:$DryRun
  Invoke-VulnAction -DryRun:$DryRun -Description "disable Kerberos pre-auth for '$name'" -Action {
    Set-ADAccountControl -Identity $name -DoesNotRequirePreAuth $true
  }
  Write-Good "AS-REP roastable: $name"
}

Write-BlueTeam "Detect: Event 4768 with pre-auth type 0; audit userAccountControl for DONT_REQ_PREAUTH (Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true}); remove the flag and enforce strong passwords."
