<#
.SYNOPSIS
  Grant DCSync rights (domain replication) to a low-privileged principal.

.DESCRIPTION
  DCSync lets a principal with the "Replicating Directory Changes" extended
  rights pull password hashes for any account (including krbtgt) straight from a
  DC, as if it were a DC itself. This grants those extended rights on the domain
  head to the configured identity. Undo removes them.

  Spec shape:  { "identity": "jdoe" }
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

Write-Step ("{0} DCSync rights" -f ($(if ($Undo) { 'Removing' } else { 'Granting' })))

$identity = $Spec.identity
if (-not $identity) { Write-Warn "dcsync: no 'identity' in spec; skipping."; return }

# Replication extended-right GUIDs.
$replGuids = @(
  [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
  [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes-All
)

if ($DryRun) {
  $verb = if ($Undo) { 'remove' } else { 'grant' }
  Write-Host -ForegroundColor DarkGray "    [dry-run] would: $verb DCSync (Get-Changes + Get-Changes-All) for '$identity' on the domain head"
}
else {
  $sid = Get-ADObjectSid -Identity $identity
  $domainDN = Get-DomainDN
  $extRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
  foreach ($g in $replGuids) {
    Set-ADAceForIdentity -TargetDN $domainDN -Sid $sid -Rights $extRight -ObjectType $g -Remove:$Undo
  }
  if (-not $Undo) { Write-Good "DCSync: '$identity' can now replicate secrets from the domain." }
}

Write-BlueTeam "Detect: Event 4662 with the replication GUIDs by non-DC accounts; network IDS for DRSUAPI/GetNCChanges from non-DCs; audit who holds Get-Changes* on the domain head and remove unexpected principals."
