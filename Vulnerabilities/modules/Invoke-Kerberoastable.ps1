<#
.SYNOPSIS
  Create Kerberoastable service accounts (user accounts with an SPN + weak password).

.DESCRIPTION
  An attacker can request a service ticket (TGS) for any account that has a
  Service Principal Name, then crack it offline to recover the password. This
  creates dedicated lab service accounts with SPNs and deliberately weak
  passwords. Undo deletes exactly the accounts it created.

  Spec shape:
    { "accounts": [ { "name": "svc-sql", "spn": "MSSQLSvc/sql01.moros.local:1433", "password": "Summer2024" } ] }
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

Write-Step ("{0} Kerberoastable service accounts" -f ($(if ($Undo) { 'Removing' } else { 'Creating' })))

foreach ($acct in @($Spec.accounts)) {
  if (-not $acct) { continue }
  $name = $acct.name
  $spn  = $acct.spn

  if ($Undo) {
    if ($DryRun) { Write-Host -ForegroundColor DarkGray "    [dry-run] would: delete service account '$name'"; continue }
    $u = Get-ADUser -Filter "SamAccountName -eq '$name'" -Properties info, servicePrincipalName -ErrorAction SilentlyContinue
    if (-not $u) { Write-Warn "Service account '$name' not found; skipping."; continue }
    if (Test-LabCreated $u) {
      Invoke-VulnAction -Description "delete lab service account '$name'" -Action { Remove-ADUser -Identity $u.SamAccountName -Confirm:$false }
    }
    else {
      Invoke-VulnAction -Description "clear SPN '$spn' from pre-existing account '$name'" -Action {
        Set-ADUser -Identity $u.SamAccountName -ServicePrincipalNames @{ Remove = $spn }
      }
    }
    continue
  }

  $pw = if ($acct.password) { $acct.password } else { 'Summer2024' }
  $res = Resolve-ADUserOrCreate -Name $name -Password $pw -DryRun:$DryRun
  Invoke-VulnAction -DryRun:$DryRun -Description "set SPN '$spn' on '$name'" -Action {
    Set-ADUser -Identity $res.Sam -ServicePrincipalNames @{ Add = $spn }
  }
  Write-Good "Kerberoastable: $name (SPN $spn)"
}

Write-BlueTeam "Detect: Event 4769 (TGS requests), esp. RC4 (0x17) tickets for non-machine accounts; audit SPNs on user accounts (Get-ADUser -Filter {ServicePrincipalName -like '*'}); use long/random (gMSA) service passwords."
