<#
.SYNOPSIS
  Install AD DS and promote this server to the first DC of a new forest.

.DESCRIPTION
  Installs the AD-Domain-Services feature then runs Install-ADDSForest. This
  REBOOTS the machine on success, so the orchestrator registers a resume task
  before calling it. Can also be run standalone.

.EXAMPLE
  .\Install-DC.ps1 -DomainName moros.local -NetbiosName MOROS -SafeModePassword 'DSRM-P@ss!'
#>
# Top-level params are optional so the file can be dot-sourced for its function
# without mandatory-parameter binding; Install-DC enforces requirements.
[CmdletBinding()]
param(
  [string]$DomainName,
  [string]$NetbiosName,
  [string]$SafeModePassword,
  [string]$ForestMode = 'WinThreshold',
  [string]$DomainMode = 'WinThreshold',
  [switch]$DryRun
)

. (Join-Path $PSScriptRoot 'Common.ps1')

function Install-DC {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [string]$DomainName,
    [Parameter(Mandatory)] [string]$NetbiosName,
    [Parameter(Mandatory)] [string]$SafeModePassword,
    [string]$ForestMode = 'WinThreshold',
    [string]$DomainMode = 'WinThreshold',
    [switch]$DryRun
  )

  Write-Step "Promoting this server to a Domain Controller for '$DomainName'"

  if (Test-IsDomainController) {
    Write-Good "This machine is already a Domain Controller. Skipping promotion."
    return [pscustomobject]@{ RebootRequired = $false }
  }

  if (-not $DryRun) { Assert-IsAdmin }

  Invoke-LabAction -DryRun:$DryRun -Description "Install-WindowsFeature AD-Domain-Services -IncludeManagementTools" -Action {
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
  }

  $securePw = ConvertTo-SecureString $SafeModePassword -AsPlainText -Force

  Invoke-LabAction -DryRun:$DryRun -Description "Install-ADDSForest -DomainName $DomainName -DomainNetbiosName $NetbiosName (forest=$ForestMode domain=$DomainMode) -InstallDns  [REBOOTS]" -Action {
    Import-Module ADDSDeployment
    Install-ADDSForest `
      -DomainName $DomainName `
      -DomainNetbiosName $NetbiosName `
      -ForestMode $ForestMode `
      -DomainMode $DomainMode `
      -SafeModeAdministratorPassword $securePw `
      -InstallDns `
      -NoRebootOnCompletion:$false `
      -Force
  }

  # Install-ADDSForest triggers the reboot itself; this is informational.
  return [pscustomobject]@{ RebootRequired = $true }
}

if (-not $DomainName -or -not $NetbiosName -or -not $SafeModePassword) {
  throw "Install-DC.ps1 requires -DomainName, -NetbiosName and -SafeModePassword."
}
Install-DC -DomainName $DomainName -NetbiosName $NetbiosName -SafeModePassword $SafeModePassword `
  -ForestMode $ForestMode -DomainMode $DomainMode -DryRun:$DryRun
