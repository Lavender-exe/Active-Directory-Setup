<#
.SYNOPSIS
  Configure hostname, static IPv4 and DNS on the server that will become the DC.

.DESCRIPTION
  Replaces the manual sconfig steps from the README. Idempotent: it only changes
  settings that are not already correct. A hostname change requires a reboot;
  this script reports that via its return value so the caller (Deploy-ADLab.ps1)
  can sequence the reboot. Can be run standalone or dot-sourced.

.EXAMPLE
  .\Set-DCNetwork.ps1 -Hostname DC01 -IpAddress 10.0.0.10 -PrefixLength 24 -Gateway 10.0.0.1 -DnsServer 127.0.0.1
#>
# NOTE: top-level params are all optional so this file can be dot-sourced
# (for its function) without triggering mandatory-parameter binding. The inner
# Set-DCNetwork function enforces what is actually required.
[CmdletBinding()]
param(
  [string]$Hostname,
  [string]$IpAddress,
  [int]$PrefixLength = 24,
  [string]$Gateway,
  [string]$DnsServer = '127.0.0.1',
  [string]$InterfaceAlias,
  [switch]$DryRun
)

. (Join-Path $PSScriptRoot 'Common.ps1')

function Set-DCNetwork {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [string]$Hostname,
    [string]$IpAddress,
    [int]$PrefixLength = 24,
    [string]$Gateway,
    [string]$DnsServer = '127.0.0.1',
    [string]$InterfaceAlias,
    [switch]$DryRun
  )

  Write-Step "Configuring network for '$Hostname'"
  $rebootRequired = $false

  # --- Pick the network adapter ---------------------------------------------
  if (-not $IpAddress) {
    Write-Info "No static IP requested; leaving IP/DNS as-is."
  }
  else {
    if (-not $InterfaceAlias) {
      $adapter = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
      if (-not $adapter) { $adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1 }
      if (-not $adapter) { throw "No active network adapter found; pass -InterfaceAlias explicitly." }
      $InterfaceAlias = $adapter.Name
    }
    Write-Info "Using interface '$InterfaceAlias'."

    # --- Static IPv4 --------------------------------------------------------
    $existing = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object IPAddress -eq $IpAddress
    if ($existing) {
      Write-Good "IP $IpAddress already set on '$InterfaceAlias'."
    }
    else {
      Invoke-LabAction -DryRun:$DryRun -Description "set static IP $IpAddress/$PrefixLength (gw $Gateway) on '$InterfaceAlias'" -Action {
        # Clear any DHCP / stale config on this interface first.
        Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
          Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        Set-NetIPInterface -InterfaceAlias $InterfaceAlias -Dhcp Disabled -ErrorAction SilentlyContinue

        $params = @{ InterfaceAlias = $InterfaceAlias; IPAddress = $IpAddress; PrefixLength = $PrefixLength; AddressFamily = 'IPv4' }
        if ($Gateway) { $params['DefaultGateway'] = $Gateway }
        New-NetIPAddress @params | Out-Null
      }
    }

    # --- DNS ----------------------------------------------------------------
    Invoke-LabAction -DryRun:$DryRun -Description "set DNS server to $DnsServer on '$InterfaceAlias'" -Action {
      Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $DnsServer
    }
  }

  # --- Hostname -------------------------------------------------------------
  if ($env:COMPUTERNAME -eq $Hostname) {
    Write-Good "Hostname is already '$Hostname'."
  }
  else {
    Invoke-LabAction -DryRun:$DryRun -Description "rename computer '$($env:COMPUTERNAME)' -> '$Hostname'" -Action {
      Rename-Computer -NewName $Hostname -Force
    }
    $rebootRequired = $true
    Write-Warn "Hostname change requires a reboot before promotion."
  }

  return [pscustomobject]@{ RebootRequired = $rebootRequired }
}

if (-not $Hostname) { throw "Set-DCNetwork.ps1 requires -Hostname." }
Set-DCNetwork -Hostname $Hostname -IpAddress $IpAddress -PrefixLength $PrefixLength `
  -Gateway $Gateway -DnsServer $DnsServer -InterfaceAlias $InterfaceAlias -DryRun:$DryRun
