<#
.SYNOPSIS
  Grant dangerous DACL rights (e.g. GenericAll / WriteDacl) on AD objects.

.DESCRIPTION
  Over-permissive ACLs are the backbone of most BloodHound attack paths: a
  low-privileged principal that has GenericAll / WriteDacl / WriteOwner over a
  group or user can take it over (reset its password, add itself to it, etc.).
  This grants the configured rights from an identity onto a target object. Undo
  removes exactly those ACEs.

  Spec shape:
    { "grants": [ { "identity": "jdoe", "target": "Domain Admins", "right": "GenericAll" } ] }
  Supported rights: GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty.
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

Write-Step ("{0} dangerous ACLs" -f ($(if ($Undo) { 'Removing' } else { 'Granting' })))

foreach ($grant in @($Spec.grants)) {
  if (-not $grant) { continue }
  $identity = $grant.identity
  $target   = $grant.target
  $right    = if ($grant.right) { $grant.right } else { 'GenericAll' }

  if ($DryRun) {
    $verb = if ($Undo) { 'remove' } else { 'grant' }
    Write-Host -ForegroundColor DarkGray "    [dry-run] would: $verb [$right] for '$identity' on '$target'"
    continue
  }

  $sid = Get-ADObjectSid -Identity $identity
  # Resolve target DN (group or user).
  $obj = Get-ADObject -Filter "Name -eq '$target'" -ErrorAction SilentlyContinue
  if (-not $obj) { $obj = Get-ADObject -Filter "SamAccountName -eq '$target'" -ErrorAction SilentlyContinue }
  if (-not $obj) { Write-Warn "Target '$target' not found; skipping."; continue }

  $rights = [System.DirectoryServices.ActiveDirectoryRights]$right
  Set-ADAceForIdentity -TargetDN $obj.DistinguishedName -Sid $sid -Rights $rights -Remove:$Undo -DryRun:$DryRun
  if (-not $Undo) { Write-Good "ACL: '$identity' now has $right over '$target'" }
}

Write-BlueTeam "Detect: run BloodHound and review inbound control to Tier-0 objects; audit DACL changes (Event 5136) on privileged groups; remove non-admin ACEs on Domain Admins / AdminSDHolder."
