<#
.SYNOPSIS
  Expose credentials the way real environments accidentally do.

.DESCRIPTION
  Stashes plaintext-ish secrets in user 'description' fields (a classic easy win
  for attackers enumerating the domain) and flags accounts PasswordNeverExpires.
  Undo clears the descriptions it set and reverts the flag.

  Spec shape:
    {
      "descriptions": [ { "user": "jdoe", "text": "temp pw: Password123!" } ],
      "passwordNeverExpires": [ "svc-sql" ]
    }
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

Write-Step ("{0} credential exposure" -f ($(if ($Undo) { 'Reverting' } else { 'Creating' })))

foreach ($d in @($Spec.descriptions)) {
  if (-not $d) { continue }
  $user = $d.user
  if (-not $DryRun) { $null = Resolve-ADUserOrCreate -Name $user }
  if ($Undo) {
    Invoke-VulnAction -DryRun:$DryRun -Description "clear description on '$user'" -Action {
      Set-ADUser -Identity $user -Description ' '
    }
  }
  else {
    Invoke-VulnAction -DryRun:$DryRun -Description "set telltale description on '$user'" -Action {
      Set-ADUser -Identity $user -Description $d.text
    }
    Write-Good "Credential in description: $user"
  }
}

foreach ($user in @($Spec.passwordNeverExpires)) {
  if (-not $user) { continue }
  if (-not $DryRun) { $null = Resolve-ADUserOrCreate -Name $user }
  Invoke-VulnAction -DryRun:$DryRun -Description ("{0} PasswordNeverExpires on '$user'" -f ($(if ($Undo) { 'clear' } else { 'set' }))) -Action {
    Set-ADUser -Identity $user -PasswordNeverExpires (-not $Undo)
  }
}

Write-BlueTeam "Detect: scan description/info/comment fields for secrets (Get-ADUser -Filter * -Properties Description | ? Description -match 'pw|pass'); audit PasswordNeverExpires accounts; rotate any exposed secrets."
