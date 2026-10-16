<#
.SYNOPSIS
  AD FS misconfigurations that enable Golden SAML / domain compromise.

.DESCRIPTION
  The high-impact AD FS attack is Golden SAML: steal the token-signing key (and
  the DKM master key that protects it) and forge SAML tokens for any user to any
  relying party. Two realistic lab misconfigurations make this devastating:

    overprivilegedServiceAccount - the AD FS service account is a member of a
        privileged group (e.g. Domain Admins). Compromising AD FS then equals
        Domain Admin. (A very common real-world mistake.)
    dkmKeyReadAccess - a low-privileged principal is granted read access to the
        AD FS DKM key container in AD, letting them derive the token-signing
        key and forge tokens (Golden SAML) without touching the AD FS host.

  Best-effort and reversible. If AD FS isn't deployed, the DKM part prints
  guidance instead of failing.

  Spec shape:
    {
      "serviceAccount": "svc-adfs",
      "addToGroup": "Domain Admins",
      "dkmKeyReadIdentity": "asrep-user"
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

Write-Step ("{0} AD FS misconfigurations" -f ($(if ($Undo) { 'Reverting' } else { 'Creating' })))

# --- Over-privileged service account ---------------------------------------
if ($Spec.serviceAccount -and $Spec.addToGroup) {
  $svc = $Spec.serviceAccount
  $grp = $Spec.addToGroup
  if (-not $DryRun -and -not $Undo) { $null = Resolve-ADUserOrCreate -Name $svc }
  if ($Undo) {
    Invoke-VulnAction -DryRun:$DryRun -Description "remove AD FS service account '$svc' from '$grp'" -Action {
      Remove-ADGroupMember -Identity $grp -Members $svc -Confirm:$false -ErrorAction SilentlyContinue
    }
  }
  else {
    Invoke-VulnAction -DryRun:$DryRun -Description "add AD FS service account '$svc' to '$grp'" -Action {
      Add-ADGroupMember -Identity $grp -Members $svc
    }
    Write-Good "AD FS svc '$svc' is now a member of '$grp' (compromise of AD FS => $grp)."
  }
}

# --- DKM key read access (Golden SAML enabler) ------------------------------
if ($Spec.dkmKeyReadIdentity) {
  $id = $Spec.dkmKeyReadIdentity
  if ($DryRun) {
    $verb = if ($Undo) { 'remove' } else { 'grant' }
    Write-Host -ForegroundColor DarkGray "    [dry-run] would: $verb read access on the AD FS DKM container for '$id'"
  }
  else {
    try {
      $domainDN = Get-DomainDN
      # AD FS stores its DKM master key under CN=ADFS,CN=Microsoft,CN=Program Data,<domainDN>.
      $pd = Get-ADObject -Filter "Name -eq 'ADFS'" -SearchBase "CN=Microsoft,CN=Program Data,$domainDN" -ErrorAction SilentlyContinue
      if (-not $pd) {
        Write-Warn "AD FS DKM container not found (AD FS not deployed with a DKM key?). Skipping."
        Write-BlueTeam "Manual: the DKM key lives under CN=ADFS,CN=Microsoft,CN=Program Data,<domainDN>; only the AD FS service account should be able to read it."
      }
      else {
        $sid = Get-ADObjectSid -Identity $id
        Set-ADAceForIdentity -TargetDN $pd.DistinguishedName -Sid $sid `
          -Rights ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead) -Remove:$Undo
        if (-not $Undo) { Write-Good "DKM read granted to '$id' (Golden SAML enabler)." }
      }
    }
    catch { Write-Warn "DKM ACL step failed: $($_.Exception.Message)" }
  }
}

Write-BlueTeam "Detect: audit AD FS service-account group membership (should NOT be privileged); monitor 4662 reads on the DKM container; watch for abnormal SAML token lifetimes/claims and 'Set-AdfsProperties'/token-signing cert exports; rotate token-signing certs and the DKM key if exposed."
