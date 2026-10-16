<#
.SYNOPSIS
  Create accounts with unconstrained or constrained Kerberos delegation.

.DESCRIPTION
  Delegation lets a service impersonate users to other services. Unconstrained
  delegation caches users' TGTs (any user that authenticates can be impersonated
  anywhere); constrained delegation (esp. with protocol transition) can be
  abused to impersonate arbitrary users to the allowed SPNs. This creates
  dedicated lab accounts configured accordingly. Undo deletes the accounts it
  created (or reverts the flags on pre-existing ones).

  -DelegationType Unconstrained | Constrained
  Spec (unconstrained): { "accounts": [ { "name": "svc-web", "password": "Password1" } ] }
  Spec (constrained):   { "accounts": [ { "name": "svc-app", "password": "Password1", "allowedTo": [ "cifs/dc01.moros.local" ] } ] }
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] $Spec,
  [Parameter(Mandatory)] [ValidateSet('Unconstrained', 'Constrained')] [string]$DelegationType,
  [string]$Domain,
  [switch]$Undo,
  [switch]$DryRun
)
. (Join-Path $PSScriptRoot 'Common.ps1')
if (-not $DryRun) { Import-ADModuleOrThrow }

Write-Step ("{0} {1} delegation accounts" -f ($(if ($Undo) { 'Removing' } else { 'Creating' })), $DelegationType.ToLower())

foreach ($acct in @($Spec.accounts)) {
  if (-not $acct) { continue }
  $name = $acct.name

  if ($Undo) {
    if (-not $DryRun) {
      $u = Get-ADUser -Filter "SamAccountName -eq '$name'" -Properties info -ErrorAction SilentlyContinue
      if (-not $u) { Write-Warn "Account '$name' not found; skipping."; continue }
      if (Test-LabCreated $u) {
        Invoke-VulnAction -Description "delete lab account '$name'" -Action { Remove-ADUser -Identity $u.SamAccountName -Confirm:$false }
        continue
      }
    }
    Invoke-VulnAction -DryRun:$DryRun -Description "disable delegation flags on '$name'" -Action {
      Set-ADAccountControl -Identity $name -TrustedForDelegation $false -TrustedToAuthForDelegation $false
      Set-ADUser -Identity $name -Clear 'msDS-AllowedToDelegateTo' -ErrorAction SilentlyContinue
    }
    continue
  }

  $pw = if ($acct.password) { $acct.password } else { 'Password1' }
  $res = Resolve-ADUserOrCreate -Name $name -Password $pw -DryRun:$DryRun

  if ($DelegationType -eq 'Unconstrained') {
    Invoke-VulnAction -DryRun:$DryRun -Description "set TRUSTED_FOR_DELEGATION (unconstrained) on '$name'" -Action {
      Set-ADAccountControl -Identity $res.Sam -TrustedForDelegation $true
    }
  }
  else {
    $targets = @($acct.allowedTo)
    Invoke-VulnAction -DryRun:$DryRun -Description "set constrained delegation (+ protocol transition) on '$name' -> $($targets -join ', ')" -Action {
      Set-ADAccountControl -Identity $res.Sam -TrustedToAuthForDelegation $true
      Set-ADUser -Identity $res.Sam -Add @{ 'msDS-AllowedToDelegateTo' = $targets }
    }
  }
  Write-Good "$DelegationType delegation: $name"
}

if ($DelegationType -eq 'Unconstrained') {
  Write-BlueTeam "Detect: audit accounts with TRUSTED_FOR_DELEGATION (Get-ADComputer/User -Filter {TrustedForDelegation -eq `$true}); never allow it on non-DC hosts; mark sensitive accounts 'Account is sensitive and cannot be delegated' / add to Protected Users."
}
else {
  Write-BlueTeam "Detect: audit msDS-AllowedToDelegateTo and TRUSTED_TO_AUTH_FOR_DELEGATION; watch S4U2Self/S4U2Proxy (4769) activity; restrict who can configure delegation."
}
