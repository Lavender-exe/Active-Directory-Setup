<#
.SYNOPSIS
  Install AD management tooling (RSAT) and verify AD Web Services (ADWS).

.DESCRIPTION
  ADWS ships with the AD-Domain-Services role, so on a DC this is mostly a
  presence/health check plus installing the RSAT management features. On a
  non-server (client) OS the matching Add-WindowsCapability names are used.

.EXAMPLE
  .\Install-RSAT.ps1
#>
[CmdletBinding()]
param(
  [switch]$DryRun
)

. (Join-Path $PSScriptRoot 'Common.ps1')

function Install-RSATRole {
  [CmdletBinding()]
  param([switch]$DryRun)

  Write-Step "Installing RSAT / AD management tooling"
  if (-not $DryRun) { Assert-IsAdmin }

  $isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1  # 1 = workstation

  if ($isServer) {
    Invoke-LabAction -DryRun:$DryRun -Description "Install-WindowsFeature RSAT-AD-Tools, RSAT-ADDS, RSAT-ADCS-Mgmt, RSAT-ADFS-Mgmt" -Action {
      Install-WindowsFeature RSAT-AD-Tools, RSAT-ADDS, RSAT-ADCS-Mgmt, RSAT-ADFS-Mgmt -ErrorAction SilentlyContinue | Out-Null
    }
  }
  else {
    Invoke-LabAction -DryRun:$DryRun -Description "Add-WindowsCapability (RSAT AD DS / ADCS / ADFS tools) on client OS" -Action {
      Get-WindowsCapability -Online |
        Where-Object { $_.Name -like 'Rsat.ActiveDirectory*' -or $_.Name -like 'Rsat.CertificateServices*' -or $_.Name -like 'Rsat.ADFS*' } |
        Where-Object State -ne 'Installed' |
        ForEach-Object { Add-WindowsCapability -Online -Name $_.Name | Out-Null }
    }
  }

  # --- ADWS health ----------------------------------------------------------
  if ($DryRun) {
    Write-Host -ForegroundColor DarkGray "    [dry-run] would: check ADWS service status"
  }
  else {
    $adws = Get-Service -Name ADWS -ErrorAction SilentlyContinue
    if (-not $adws) {
      Write-Warn "ADWS service not found. It installs with the AD DS role; is this a DC?"
    }
    elseif ($adws.Status -ne 'Running') {
      Write-Info "ADWS present but not running; starting it."
      Start-Service ADWS
      Write-Good "ADWS started."
    }
    else {
      Write-Good "ADWS is present and running."
    }
  }
}

Install-RSATRole -DryRun:$DryRun
