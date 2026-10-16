<#
.SYNOPSIS
  Install and configure an AD FS farm (first node).

.DESCRIPTION
  Installs the ADFS-Federation role and runs Install-AdfsFarm. AD FS needs a TLS
  certificate and a service account. For a lab, if no -CertThumbprint is given a
  self-signed certificate for -ServiceFqdn is generated automatically. Must run
  on a domain-joined machine.

.EXAMPLE
  .\Install-ADFS.ps1 -ServiceFqdn adfs.moros.local -ServiceAccount MOROS\svc-adfs -ServiceAccountPassword 'P@ss!'
#>
# Top-level params are optional so the file can be dot-sourced for its function
# without mandatory-parameter binding; Install-ADFSRole enforces requirements.
[CmdletBinding()]
param(
  [string]$ServiceFqdn,
  [string]$DisplayName = 'Lab ADFS',
  [string]$CertThumbprint,
  [string]$ServiceAccount,
  [string]$ServiceAccountPassword,
  [switch]$DryRun
)

. (Join-Path $PSScriptRoot 'Common.ps1')

function Install-ADFSRole {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [string]$ServiceFqdn,
    [string]$DisplayName = 'Lab ADFS',
    [string]$CertThumbprint,
    [Parameter(Mandatory)] [string]$ServiceAccount,
    [Parameter(Mandatory)] [string]$ServiceAccountPassword,
    [switch]$DryRun
  )

  Write-Step "Installing AD FS ('$ServiceFqdn')"
  if (-not $DryRun) { Assert-IsAdmin }

  if (-not $DryRun -and -not (Test-IsDomainJoined)) {
    throw "AD FS requires this machine to be domain-joined. Join the domain first (see Workstation\Join-AD.ps1)."
  }

  Invoke-LabAction -DryRun:$DryRun -Description "Install-WindowsFeature ADFS-Federation -IncludeManagementTools" -Action {
    Install-WindowsFeature ADFS-Federation -IncludeManagementTools | Out-Null
  }

  # --- TLS certificate ------------------------------------------------------
  $thumb = $CertThumbprint
  if (-not $thumb) {
    Invoke-LabAction -DryRun:$DryRun -Description "generate self-signed certificate for '$ServiceFqdn' (lab default)" -Action {
      $cert = New-SelfSignedCertificate -DnsName $ServiceFqdn -CertStoreLocation 'Cert:\LocalMachine\My'
      $script:AdfsThumb = $cert.Thumbprint
    }
    $thumb = if ($DryRun) { '<self-signed-thumbprint>' } else { $script:AdfsThumb }
    Write-Info "Using self-signed certificate thumbprint: $thumb"
  }
  else {
    Write-Info "Using supplied certificate thumbprint: $thumb"
  }

  # --- Service account credential ------------------------------------------
  Invoke-LabAction -DryRun:$DryRun -Description "Install-AdfsFarm -FederationServiceName '$ServiceFqdn' -FederationServiceDisplayName '$DisplayName' -ServiceAccountCredential ($ServiceAccount) -CertificateThumbprint $thumb" -Action {
    $securePw = ConvertTo-SecureString $ServiceAccountPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($ServiceAccount, $securePw)
    Import-Module ADFS
    Install-AdfsFarm `
      -FederationServiceName $ServiceFqdn `
      -FederationServiceDisplayName $DisplayName `
      -CertificateThumbprint $thumb `
      -ServiceAccountCredential $cred `
      -OverwriteConfiguration
  }

  Write-Good "AD FS install step complete. Verify with: Get-AdfsProperties"
}

if (-not $ServiceFqdn -or -not $ServiceAccount -or -not $ServiceAccountPassword) {
  throw "Install-ADFS.ps1 requires -ServiceFqdn, -ServiceAccount and -ServiceAccountPassword."
}
Install-ADFSRole -ServiceFqdn $ServiceFqdn -DisplayName $DisplayName -CertThumbprint $CertThumbprint `
  -ServiceAccount $ServiceAccount -ServiceAccountPassword $ServiceAccountPassword -DryRun:$DryRun
