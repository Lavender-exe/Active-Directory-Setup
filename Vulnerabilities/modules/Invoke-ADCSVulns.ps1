<#
.SYNOPSIS
  Publish ADCS ESC misconfigurations (ESC1, ESC2, ESC3, ESC4, ESC6).

.DESCRIPTION
  Creates vulnerable certificate templates and CA settings so defenders can hunt
  the classic AD CS escalation paths with Certify/Certipy and remediate them.
  Requires the ADCS role (add an "ADCS" role to your lab spec in
  ..\Domain Controller). Best-effort: missing pieces print guidance instead of
  failing the run. Everything is reversible with -Undo.

  Covered:
    ESC1  template: enrollee-supplies-subject + Client Authentication EKU
    ESC2  template: Any Purpose EKU (usable for client auth, and more)
    ESC3  template: Certificate Request Agent EKU (enrollment agent)
    ESC4  weak template ACL: low-priv principal gets Write control over a template
    ESC6  CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 (SAN in any request)

  Spec shape:
    {
      "templates": [
        { "type": "ESC1", "templateName": "ESC1-Vuln", "cloneFrom": "User", "enrollPrincipal": "Domain Users" },
        { "type": "ESC2", "templateName": "ESC2-AnyPurpose", "enrollPrincipal": "Domain Users" },
        { "type": "ESC3", "templateName": "ESC3-EnrollAgent", "enrollPrincipal": "Domain Users" }
      ],
      "esc4": [ { "templateName": "User", "identity": "asrep-user", "right": "WriteDacl" } ],
      "esc6": { "enabled": true }
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

# EKU / name-flag per ESC type.
$EKU = @{
  ESC1 = '1.3.6.1.5.5.7.3.2'          # Client Authentication
  ESC2 = '2.5.29.37.0'                # Any Purpose
  ESC3 = '1.3.6.1.4.1.311.20.2.1'     # Certificate Request Agent (enrollment agent)
}
$ENROLLEE_SUPPLIES_SUBJECT = 1
$CERT_ENROLL_RIGHT = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'

function Get-TemplatesDN { "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).ConfigurationNamingContext)" }

function New-VulnTemplate {
  param([string]$Name, [string]$CloneFrom, [string]$Eku, [int]$NameFlag, [string]$EnrollPrincipal)
  $templatesDN = Get-TemplatesDN
  $copyAttrs = 'pKIExpirationPeriod', 'pKIOverlapPeriod', 'pKIKeyUsage', 'pKIMaxIssuingDepth',
               'pKIDefaultKeySpec', 'pKICriticalExtensions', 'pKIDefaultCSPs', 'msPKI-Minimal-Key-Size',
               'msPKI-Template-Schema-Version'
  $src = Get-ADObject -SearchBase $templatesDN -Filter "Name -eq '$CloneFrom'" -Properties $copyAttrs -ErrorAction SilentlyContinue
  if (-not $src) {
    Write-Warn "Source template '$CloneFrom' not found (is ADCS installed?). Skipping '$Name'."
    return $false
  }
  if (Get-ADObject -SearchBase $templatesDN -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue) {
    Write-Warn "Template '$Name' already exists; skipping create."
  }
  else {
    $other = @{
      'flags'                                = 131649
      'pKIExtendedKeyUsage'                  = $Eku
      'msPKI-Certificate-Application-Policy' = $Eku
      'msPKI-Certificate-Name-Flag'          = $NameFlag
      'msPKI-Enrollment-Flag'                = 0
      'msPKI-RA-Signature'                   = 0
      'msPKI-Private-Key-Flag'               = 16
      'revision'                             = 100
    }
    foreach ($a in $copyAttrs) { if ($null -ne $src.$a) { $other[$a] = $src.$a } }
    New-ADObject -Name $Name -Type 'pKICertificateTemplate' -Path $templatesDN -DisplayName $Name -OtherAttributes $other
  }
  # Enroll right for the low-priv principal.
  $sid = Get-ADObjectSid -Identity $EnrollPrincipal
  Set-ADAceForIdentity -TargetDN "CN=$Name,$templatesDN" -Sid $sid `
    -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ObjectType $CERT_ENROLL_RIGHT
  if (Get-Command Add-CATemplate -ErrorAction SilentlyContinue) { Add-CATemplate -Name $Name -Force -ErrorAction SilentlyContinue }
  else { Write-Warn "Publish manually: certutil -SetCATemplates +$Name" }
  return $true
}

function Remove-VulnTemplate {
  param([string]$Name)
  if (Get-Command Remove-CATemplate -ErrorAction SilentlyContinue) { Remove-CATemplate -Name $Name -Force -ErrorAction SilentlyContinue }
  $obj = Get-ADObject -SearchBase (Get-TemplatesDN) -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
  if ($obj) { Remove-ADObject -Identity $obj.DistinguishedName -Confirm:$false }
}

Write-Step ("{0} ADCS ESC misconfigurations" -f ($(if ($Undo) { 'Removing' } else { 'Publishing' })))

# --- ESC1/2/3 templates -----------------------------------------------------
foreach ($t in @($Spec.templates)) {
  if (-not $t) { continue }
  $type = $t.type
  if (-not $EKU.ContainsKey($type)) { Write-Warn "Unknown template type '$type'; skipping."; continue }
  $name = if ($t.templateName) { $t.templateName } else { "$type-Vuln" }
  $clone = if ($t.cloneFrom) { $t.cloneFrom } else { 'User' }
  $princ = if ($t.enrollPrincipal) { $t.enrollPrincipal } else { 'Domain Users' }
  # ESC3 uses the subject from AD; ESC1/ESC2 let the enrollee supply it.
  $nameFlag = if ($type -eq 'ESC3') { 0 } else { $ENROLLEE_SUPPLIES_SUBJECT }

  if ($DryRun) {
    if ($Undo) { Write-Host -ForegroundColor DarkGray "    [dry-run] would: unpublish+delete template '$name' ($type)" }
    else { Write-Host -ForegroundColor DarkGray "    [dry-run] would: create $type template '$name' (clone '$clone', EKU $($EKU[$type]), enroll='$princ')" }
    continue
  }
  try {
    if ($Undo) { Invoke-VulnAction -Description "remove $type template '$name'" -Action { Remove-VulnTemplate -Name $name } }
    else {
      if (New-VulnTemplate -Name $name -CloneFrom $clone -Eku $EKU[$type] -NameFlag $nameFlag -EnrollPrincipal $princ) {
        Write-Good "$type template published: '$name' (enroll: $princ)"
      }
    }
  }
  catch { Write-Warn "$type '$name' failed: $($_.Exception.Message)" }
}

# --- ESC4: weak ACL over an existing template -------------------------------
foreach ($e in @($Spec.esc4)) {
  if (-not $e) { continue }
  $tpl = $e.templateName
  $id  = $e.identity
  $right = if ($e.right) { $e.right } else { 'WriteDacl' }
  if ($DryRun) {
    $verb = if ($Undo) { 'remove' } else { 'grant' }
    Write-Host -ForegroundColor DarkGray "    [dry-run] would (ESC4): $verb [$right] for '$id' on template '$tpl'"
    continue
  }
  try {
    $obj = Get-ADObject -SearchBase (Get-TemplatesDN) -Filter "Name -eq '$tpl'" -ErrorAction SilentlyContinue
    if (-not $obj) { Write-Warn "ESC4: template '$tpl' not found; skipping."; continue }
    $sid = Get-ADObjectSid -Identity $id
    Set-ADAceForIdentity -TargetDN $obj.DistinguishedName -Sid $sid -Rights ([System.DirectoryServices.ActiveDirectoryRights]$right) -Remove:$Undo
    if (-not $Undo) { Write-Good "ESC4: '$id' now has $right over template '$tpl'" }
  }
  catch { Write-Warn "ESC4 on '$tpl' failed: $($_.Exception.Message)" }
}

# --- ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA --------------------------
if ($Spec.esc6 -and $Spec.esc6.enabled -eq $true) {
  $flagOp = if ($Undo) { '-EDITF_ATTRIBUTESUBJECTALTNAME2' } else { '+EDITF_ATTRIBUTESUBJECTALTNAME2' }
  if ($DryRun) {
    Write-Host -ForegroundColor DarkGray "    [dry-run] would (ESC6): certutil -setreg policy\EditFlags $flagOp ; restart certsvc"
  }
  else {
    try {
      Invoke-VulnAction -Description "ESC6: certutil -setreg policy\EditFlags $flagOp" -Action {
        certutil -setreg policy\EditFlags $flagOp | Out-Null
        Restart-Service certsvc -ErrorAction SilentlyContinue
      }
      if (-not $Undo) { Write-Good "ESC6: CA now honours SAN from any request (EDITF_ATTRIBUTESUBJECTALTNAME2)." }
    }
    catch { Write-Warn "ESC6 failed (is this the CA?): $($_.Exception.Message)" }
  }
}

Write-BlueTeam "Detect: run Certify/Certipy 'find' (flags ESC1-ESC8); audit templates for enrollee-supplies-subject, Any-Purpose/No-EKU, Enrollment-Agent EKU, and low-priv Enroll/Write ACEs; check CA EditFlags for EDITF_ATTRIBUTESUBJECTALTNAME2; enable CA auditing (4886/4887) and require manager approval on auth-capable templates."
