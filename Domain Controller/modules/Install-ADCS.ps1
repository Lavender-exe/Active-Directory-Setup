<#
.SYNOPSIS
  Install Active Directory Certificate Services (an Enterprise Root CA by default).

.DESCRIPTION
  Installs the ADCS-Cert-Authority role and configures a CA. An Enterprise CA
  requires the machine to be domain-joined and the caller to be an Enterprise
  Admin. Runs unchanged on the DC itself or on a domain-joined member server.

.EXAMPLE
  .\Install-ADCS.ps1 -CaCommonName moros-CA
  .\Install-ADCS.ps1 -CaType StandaloneRootCA -CaCommonName lab-CA -ValidityYears 10
#>
# Top-level params are optional so the file can be dot-sourced for its function
# without mandatory-parameter binding; Install-ADCSRole enforces requirements.
[CmdletBinding()]
param(
  [ValidateSet('EnterpriseRootCA', 'EnterpriseSubordinateCA', 'StandaloneRootCA', 'StandaloneSubordinateCA')]
  [string]$CaType = 'EnterpriseRootCA',
  [string]$CaCommonName,
  [int]$ValidityYears = 5,
  [switch]$DryRun
)

. (Join-Path $PSScriptRoot 'Common.ps1')

function Install-ADCSRole {
  [CmdletBinding()]
  param(
    [string]$CaType = 'EnterpriseRootCA',
    [Parameter(Mandatory)] [string]$CaCommonName,
    [int]$ValidityYears = 5,
    [switch]$DryRun
  )

  Write-Step "Installing ADCS ($CaType '$CaCommonName')"
  if (-not $DryRun) { Assert-IsAdmin }

  if (-not $DryRun -and $CaType -like 'Enterprise*' -and -not (Test-IsDomainJoined)) {
    throw "An $CaType requires this machine to be domain-joined. Join the domain first (see Workstation\Join-AD.ps1) or use a Standalone CA type."
  }

  Invoke-LabAction -DryRun:$DryRun -Description "Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools" -Action {
    Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null
  }

  Invoke-LabAction -DryRun:$DryRun -Description "Install-AdcsCertificationAuthority -CAType $CaType -CACommonName '$CaCommonName' -ValidityPeriod Years -ValidityPeriodUnits $ValidityYears" -Action {
    Import-Module ADCSDeployment
    $params = @{
      CAType              = $CaType
      CACommonName        = $CaCommonName
      ValidityPeriod      = 'Years'
      ValidityPeriodUnits = $ValidityYears
      Force               = $true
    }
    # Root CAs self-sign; the install cmdlet returns a status object.
    $result = Install-AdcsCertificationAuthority @params -ErrorAction Stop
    if ($result.ErrorId -and $result.ErrorId -ne 0) {
      Write-Warn "ADCS configuration returned: $($result.ErrorString)"
    }
  }

  Write-Good "ADCS install step complete. Verify with: certutil -CAInfo"
}

if (-not $CaCommonName) { throw "Install-ADCS.ps1 requires -CaCommonName." }
Install-ADCSRole -CaType $CaType -CaCommonName $CaCommonName -ValidityYears $ValidityYears -DryRun:$DryRun
