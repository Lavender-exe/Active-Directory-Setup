<#
.SYNOPSIS
  Add a principal to a dangerous "stepping-stone to DA" group (default: DnsAdmins).

.DESCRIPTION
  Membership in some built-in groups is effectively a path to Domain Admin.
  DnsAdmins is the classic example (a member can load an arbitrary DLL into the
  DNS service, which runs as SYSTEM on the DC). This adds the configured member
  to the configured group(s). Undo removes the membership.

  Spec shape:  { "memberships": [ { "member": "jdoe", "group": "DnsAdmins" } ] }
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

Write-Step ("{0} dangerous group memberships" -f ($(if ($Undo) { 'Removing' } else { 'Adding' })))

foreach ($m in @($Spec.memberships)) {
  if (-not $m) { continue }
  $member = $m.member
  $group  = if ($m.group) { $m.group } else { 'DnsAdmins' }

  if (-not $DryRun -and -not $Undo) { $null = Resolve-ADUserOrCreate -Name $member }

  if ($Undo) {
    Invoke-VulnAction -DryRun:$DryRun -Description "remove '$member' from '$group'" -Action {
      Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false -ErrorAction SilentlyContinue
    }
  }
  else {
    Invoke-VulnAction -DryRun:$DryRun -Description "add '$member' to '$group'" -Action {
      Add-ADGroupMember -Identity $group -Members $member
    }
    Write-Good "Group abuse: '$member' added to '$group'"
  }
}

Write-BlueTeam "Detect: Event 4728/4732 (member added to security group); monitor membership of DnsAdmins, Backup Operators, Account/Server Operators, Print Operators; keep these groups empty and alert on changes."
