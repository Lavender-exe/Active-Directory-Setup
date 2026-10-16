<#
.SYNOPSIS
  Expose the AD Web Services (ADWS) recon channel for detection practice.

.DESCRIPTION
  ADWS (TCP 9389) is the SOAP interface behind the AD PowerShell module, and the
  channel modern recon tools use to enumerate a domain while avoiding classic
  LDAP telemetry (e.g. SOAPHound, SOAPy, ldapnomnom-over-ADWS). Unlike the other
  modules this plants no privilege escalation; it makes sure the ADWS recon
  surface is present and reachable so defenders can generate and tune detections
  for ADWS-based enumeration.

  It ensures the ADWS service is running and (optionally) opens an inbound
  firewall rule for 9389. Undo removes the firewall rule it created (it does not
  stop ADWS, which is a core DC service).

  Spec shape:  { "exposeFirewall": true, "firewallRuleName": "ADWS-Lab-Exposure" }
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] $Spec,
  [string]$Domain,
  [switch]$Undo,
  [switch]$DryRun
)
. (Join-Path $PSScriptRoot 'Common.ps1')

$ruleName = if ($Spec.firewallRuleName) { $Spec.firewallRuleName } else { 'ADWS-Lab-Exposure' }

Write-Step ("{0} ADWS exposure" -f ($(if ($Undo) { 'Reverting' } else { 'Enabling' })))

# --- Firewall rule ----------------------------------------------------------
if ($Spec.exposeFirewall -eq $true) {
  if ($Undo) {
    Invoke-VulnAction -DryRun:$DryRun -Description "remove firewall rule '$ruleName'" -Action {
      Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
  }
  else {
    Invoke-VulnAction -DryRun:$DryRun -Description "open inbound TCP 9389 (ADWS) from Any as '$ruleName'" -Action {
      if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP `
          -LocalPort 9389 -Action Allow -RemoteAddress Any -Profile Any | Out-Null
      }
    }
    Write-Good "ADWS reachable on TCP 9389 (rule '$ruleName')."
  }
}

# --- Ensure the service is running (apply only) -----------------------------
if (-not $Undo) {
  if ($DryRun) { Write-Host -ForegroundColor DarkGray "    [dry-run] would: ensure the ADWS service is running" }
  else {
    $svc = Get-Service -Name ADWS -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Warn "ADWS service not found (is this a DC?)." }
    elseif ($svc.Status -ne 'Running') { Start-Service ADWS; Write-Good "Started ADWS." }
    else { Write-Good "ADWS already running." }
  }
}

Write-BlueTeam "Detect: monitor TCP 9389 connections from non-admin hosts; enable Directory Service Access auditing; hunt SOAP enumeration bursts (SOAPHound/SOAPy/ldapnomnom-ADWS); restrict 9389 to admin tiers; alert on AD PowerShell/ADWS use outside management jump hosts."
